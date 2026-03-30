"""
roteador.py
Configura roteamento, NAT (nftables) e ip_forward.

Estratégia nftables:
  - Família "ip" (IPv4) — o hook nat não é suportado pela família
    "inet" em kernels anteriores ao 5.2.
  - Toda a configuração fica na tabela "moonshield".
  - Regras de FORWARD usam política accept (roteamento livre entre VLANs).
"""

import os
from .utilitarios import rodar, interface_existe


# ─────────────────────────────────────────────────────────────────────────────
# ip_forward
# ─────────────────────────────────────────────────────────────────────────────

def ativar_ip_forward() -> tuple[bool, str]:
    ok, _, err = rodar(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    if ok:
        _persistir_sysctl("net.ipv4.ip_forward", "1")
    return ok, err


def desativar_ip_forward() -> tuple[bool, str]:
    ok, _, err = rodar(["sysctl", "-w", "net.ipv4.ip_forward=0"])
    if ok:
        _persistir_sysctl("net.ipv4.ip_forward", "0")
    return ok, err


def status_ip_forward() -> str:
    """Retorna '1', '0' ou '?' """
    ok, val, _ = rodar(["sysctl", "net.ipv4.ip_forward"], silencioso=True)
    if ok and "=" in val:
        return val.split("=")[-1].strip()
    return "?"


def _persistir_sysctl(chave: str, valor: str):
    """Salva em /etc/sysctl.d/99-moonshield.conf sem duplicar a chave."""
    conf = "/etc/sysctl.d/99-moonshield.conf"
    try:
        linhas = []
        if os.path.exists(conf):
            with open(conf, "r") as f:
                linhas = f.readlines()
        linhas = [l for l in linhas if not l.strip().startswith(chave)]
        linhas.append(f"{chave} = {valor}\n")
        with open(conf, "w") as f:
            f.writelines(linhas)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Tabela nftables
# ─────────────────────────────────────────────────────────────────────────────

def limpar_tabela() -> tuple[bool, str]:
    """Remove a tabela moonshield do nftables (limpa tudo)."""
    # Tenta remover nas duas famílias para garantir limpeza total
    rodar(["nft", "delete", "table", "ip",   "moonshield"], silencioso=True)
    rodar(["nft", "delete", "table", "inet", "moonshield"], silencioso=True)
    return True, ""


def criar_tabela() -> tuple[bool, str]:
    """
    Cria a tabela moonshield com as chains necessárias.
    Retorna (True, "") em sucesso ou (False, motivo) em erro.
    """
    passos = [
        (
            "tabela ip moonshield",
            ["nft", "add", "table", "ip", "moonshield"],
        ),
        (
            "chain ms_nat_post",
            ["nft", "add", "chain", "ip", "moonshield", "ms_nat_post",
             "{ type nat hook postrouting priority 100 ; }"],
        ),
        (
            "chain ms_forward",
            ["nft", "add", "chain", "ip", "moonshield", "ms_forward",
             "{ type filter hook forward priority 0 ; policy accept ; }"],
        ),
    ]
    for descricao, cmd in passos:
        ok, _, err = rodar(cmd)
        if not ok:
            return False, f"Erro ao criar {descricao}: {err}"
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# NAT / MASQUERADE
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_masquerade(wan: str) -> tuple[bool, str]:
    """Adiciona regra MASQUERADE para a interface WAN."""
    if not interface_existe(wan):
        return False, f"Interface WAN '{wan}' não encontrada."

    ok, _, err = rodar([
        "nft", "add", "rule", "ip", "moonshield", "ms_nat_post",
        "oifname", wan, "masquerade",
    ])
    if not ok:
        return False, f"Erro ao aplicar MASQUERADE em {wan}: {err}"
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# FORWARD entre VLANs e WAN
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_forward_vlan_wan(vlan_iface: str, wan: str) -> tuple[bool, str]:
    """
    Adiciona regras de FORWARD entre uma subinterface VLAN e a WAN.
    - VLAN → WAN: accept (saída para internet)
    - WAN → VLAN: accept somente tráfego estabelecido/relacionado
    """
    erros = []

    ok1, _, e1 = rodar([
        "nft", "add", "rule", "ip", "moonshield", "ms_forward",
        "iifname", vlan_iface, "oifname", wan, "accept",
    ])
    if not ok1:
        erros.append(e1)

    ok2, _, e2 = rodar([
        "nft", "add", "rule", "ip", "moonshield", "ms_forward",
        "iifname", wan, "oifname", vlan_iface,
        "ct", "state", "established,related", "accept",
    ])
    if not ok2:
        erros.append(e2)

    if erros:
        return False, " | ".join(erros)
    return True, ""


def aplicar_forward_entre_vlans(ifaces: list[str]) -> tuple[bool, str]:
    """
    Libera tráfego entre todas as subinterfaces VLAN (roteamento livre).
    Adiciona uma regra accept para cada par (A→B e B→A).
    """
    erros = []
    for i, a in enumerate(ifaces):
        for b in ifaces[i + 1:]:
            for src, dst in [(a, b), (b, a)]:
                ok, _, err = rodar([
                    "nft", "add", "rule", "ip", "moonshield", "ms_forward",
                    "iifname", src, "oifname", dst, "accept",
                ])
                if not ok:
                    erros.append(f"{src}→{dst}: {err}")

    if erros:
        return False, " | ".join(erros)
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Aplicar configuração completa de roteamento
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_roteamento_completo(config: dict) -> list[tuple[str, bool, str]]:
    """
    Orquestra toda a configuração de roteamento a partir do dict de config.
    Retorna lista de (etapa, sucesso, mensagem).
    """
    wan   = config.get("wan_interface", "")
    trunk = config.get("trunk_interface", "")
    vlans = config.get("vlans", [])

    etapas: list[tuple[str, bool, str]] = []

    # 1. ip_forward
    ok, err = ativar_ip_forward()
    etapas.append(("ip_forward", ok, err if not ok else "Ativado"))

    # 2. Limpa tabela antiga e recria do zero
    limpar_tabela()
    ok, err = criar_tabela()
    etapas.append(("Tabela nftables", ok, err if not ok else "Criada"))
    if not ok:
        return etapas  # Sem tabela não adianta continuar

    # 3. MASQUERADE na WAN
    ok, err = aplicar_masquerade(wan)
    etapas.append((f"MASQUERADE ({wan})", ok, err if not ok else "Aplicado"))

    # 4. FORWARD VLAN → WAN para cada VLAN
    ifaces_vlan = []
    for vlan in vlans:
        vlan_iface = f"{trunk}.{vlan['id']}"
        ifaces_vlan.append(vlan_iface)
        ok, err = aplicar_forward_vlan_wan(vlan_iface, wan)
        etapas.append((
            f"FORWARD {vlan_iface} ↔ {wan}",
            ok,
            err if not ok else "Aplicado",
        ))

    # 5. FORWARD entre VLANs (roteamento livre)
    if len(ifaces_vlan) >= 2:
        ok, err = aplicar_forward_entre_vlans(ifaces_vlan)
        etapas.append(("FORWARD inter-VLAN", ok, err if not ok else "Aplicado"))

    return etapas


# ─────────────────────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────────────────────

def listar_regras_nat() -> list[str]:
    """Retorna as linhas de MASQUERADE/SNAT da chain ms_nat_post."""
    ok, saida, _ = rodar(
        "nft list chain ip moonshield ms_nat_post 2>/dev/null",
        silencioso=True,
    )
    if not ok or not saida:
        return []
    return [l.strip() for l in saida.splitlines() if "masquerade" in l or "snat" in l]


def listar_rotas() -> list[str]:
    """Retorna as rotas do sistema."""
    ok, saida, _ = rodar(["ip", "route", "show"], silencioso=True)
    return saida.splitlines() if ok else []