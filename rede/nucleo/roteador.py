"""
rede/nucleo/roteador.py
──────────────────────────────────────────────────────────────────────
Configura roteamento, NAT (nftables) e ip_forward.

Estratégia nftables:
  - Família "ip" (IPv4) — o hook nat não é suportado pela família
    "inet" em kernels anteriores ao 5.2.
  - Toda a configuração fica na tabela "netforge" (isolada do MoonShield).
  - Regras de FORWARD usam política accept (roteamento livre).
  - Suporta roteamento direto entre interfaces físicas sem VLANs
    (ex: enp0s8 → enp0s9) via aplicar_forward_entre_interfaces().
──────────────────────────────────────────────────────────────────────
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
# Tabela nftables — usa "netforge" para não conflitar com o MoonShield
# ─────────────────────────────────────────────────────────────────────────────

def limpar_tabela() -> tuple[bool, str]:
    """Remove a tabela netforge do nftables."""
    rodar(["nft", "delete", "table", "ip", "netforge"], silencioso=True)
    return True, ""


def criar_tabela() -> tuple[bool, str]:
    """
    Cria a tabela netforge com as chains necessárias.
    Retorna (True, "") em sucesso ou (False, motivo) em erro.
    """
    passos = [
        (
            "tabela ip netforge",
            ["nft", "add", "table", "ip", "netforge"],
        ),
        (
            "chain ms_nat_post",
            ["nft", "add", "chain", "ip", "netforge", "ms_nat_post",
             "{ type nat hook postrouting priority 100 ; }"],
        ),
        (
            "chain ms_forward",
            ["nft", "add", "chain", "ip", "netforge", "ms_forward",
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
        "nft", "add", "rule", "ip", "netforge", "ms_nat_post",
        "oifname", wan, "masquerade",
    ])
    if not ok:
        return False, f"Erro ao aplicar MASQUERADE em {wan}: {err}"
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# FORWARD direto entre interfaces físicas (sem VLAN)
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_forward_entre_interfaces(origem: str, destino: str) -> tuple[bool, str]:
    """
    Libera roteamento bidirecional entre duas interfaces físicas quaisquer.
    Ex: enp0s8 ↔ enp0s9

    - origem → destino: accept (tráfego livre)
    - destino → origem: accept tráfego estabelecido/relacionado (resposta)
    - destino → origem: accept (bidirecional completo se necessário)

    Usa política bidirecional completa (accept nos dois sentidos),
    adequado para roteamento interno entre segmentos de rede.
    """
    if not interface_existe(origem):
        return False, f"Interface '{origem}' não encontrada."
    if not interface_existe(destino):
        return False, f"Interface '{destino}' não encontrada."

    erros = []

    # origem → destino
    ok1, _, e1 = rodar([
        "nft", "add", "rule", "ip", "netforge", "ms_forward",
        "iifname", origem, "oifname", destino, "accept",
    ])
    if not ok1:
        erros.append(f"{origem}→{destino}: {e1}")

    # destino → origem
    ok2, _, e2 = rodar([
        "nft", "add", "rule", "ip", "netforge", "ms_forward",
        "iifname", destino, "oifname", origem, "accept",
    ])
    if not ok2:
        erros.append(f"{destino}→{origem}: {e2}")

    if erros:
        return False, " | ".join(erros)
    return True, ""


def aplicar_forward_interface_wan(lan: str, wan: str) -> tuple[bool, str]:
    """
    Libera roteamento entre uma interface LAN qualquer e a WAN.
    - LAN → WAN: accept (saída para internet)
    - WAN → LAN: accept somente tráfego estabelecido/relacionado
    """
    if not interface_existe(lan):
        return False, f"Interface LAN '{lan}' não encontrada."
    if not interface_existe(wan):
        return False, f"Interface WAN '{wan}' não encontrada."

    erros = []

    ok1, _, e1 = rodar([
        "nft", "add", "rule", "ip", "netforge", "ms_forward",
        "iifname", lan, "oifname", wan, "accept",
    ])
    if not ok1:
        erros.append(e1)

    ok2, _, e2 = rodar([
        "nft", "add", "rule", "ip", "netforge", "ms_forward",
        "iifname", wan, "oifname", lan,
        "ct", "state", "established,related", "accept",
    ])
    if not ok2:
        erros.append(e2)

    if erros:
        return False, " | ".join(erros)
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# FORWARD entre VLANs e WAN (mantido para compatibilidade)
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_forward_vlan_wan(vlan_iface: str, wan: str) -> tuple[bool, str]:
    """
    Adiciona regras de FORWARD entre uma subinterface VLAN e a WAN.
    - VLAN → WAN: accept
    - WAN → VLAN: accept somente tráfego estabelecido/relacionado
    """
    return aplicar_forward_interface_wan(vlan_iface, wan)


def aplicar_forward_entre_vlans(ifaces: list[str]) -> tuple[bool, str]:
    """
    Libera tráfego entre todas as subinterfaces VLAN (roteamento livre).
    Adiciona uma regra accept para cada par (A→B e B→A).
    """
    erros = []
    for i, a in enumerate(ifaces):
        for b in ifaces[i + 1:]:
            ok, err = aplicar_forward_entre_interfaces(a, b)
            if not ok:
                erros.append(err)

    if erros:
        return False, " | ".join(erros)
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Aplicar configuração completa de roteamento
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_roteamento_completo(config: dict) -> list[tuple[str, bool, str]]:
    """
    Orquestra toda a configuração de roteamento a partir do dict de config.

    Campos suportados no config:
      wan_interface   — interface de saída para internet (ex: enp0s3)
      trunk_interface — interface trunk para VLANs (ex: enp0s2)
      vlans           — lista de {'id': 10, 'nome': 'LAN'} para VLANs
      rotas_diretas   — lista de {'origem': 'enp0s8', 'destino': 'enp0s9'}
                        para roteamento entre interfaces físicas sem VLAN

    Retorna lista de (etapa, sucesso, mensagem).
    """
    wan          = config.get("wan_interface", "")
    trunk        = config.get("trunk_interface", "")
    vlans        = config.get("vlans", [])
    rotas_diretas = config.get("rotas_diretas", [])

    etapas: list[tuple[str, bool, str]] = []

    # 1. ip_forward
    ok, err = ativar_ip_forward()
    etapas.append(("ip_forward", ok, err if not ok else "Ativado"))

    # 2. Limpa tabela antiga e recria do zero
    limpar_tabela()
    ok, err = criar_tabela()
    etapas.append(("Tabela nftables (netforge)", ok, err if not ok else "Criada"))
    if not ok:
        return etapas

    # 3. MASQUERADE na WAN (se WAN definida)
    if wan:
        ok, err = aplicar_masquerade(wan)
        etapas.append((f"MASQUERADE ({wan})", ok, err if not ok else "Aplicado"))

    # 4. Roteamento direto entre interfaces físicas (sem VLAN)
    for rota in rotas_diretas:
        origem  = rota.get("origem", "")
        destino = rota.get("destino", "")
        if not origem or not destino:
            continue
        ok, err = aplicar_forward_entre_interfaces(origem, destino)
        etapas.append((
            f"FORWARD direto {origem} ↔ {destino}",
            ok,
            err if not ok else "Aplicado",
        ))
        # MASQUERADE automático se destino for WAN
        if destino == wan or origem == wan:
            pass  # MASQUERADE já aplicado no passo 3

    # 5. FORWARD VLAN → WAN para cada VLAN
    ifaces_vlan = []
    for vlan in vlans:
        vlan_iface = f"{trunk}.{vlan['id']}"
        ifaces_vlan.append(vlan_iface)
        if wan:
            ok, err = aplicar_forward_vlan_wan(vlan_iface, wan)
            etapas.append((
                f"FORWARD {vlan_iface} ↔ {wan}",
                ok,
                err if not ok else "Aplicado",
            ))

    # 6. FORWARD entre VLANs (roteamento livre)
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
        "nft list chain ip netforge ms_nat_post 2>/dev/null",
        silencioso=True,
    )
    if not ok or not saida:
        return []
    return [l.strip() for l in saida.splitlines() if "masquerade" in l or "snat" in l]


def listar_rotas() -> list[str]:
    """Retorna as rotas do sistema."""
    ok, saida, _ = rodar(["ip", "route", "show"], silencioso=True)
    return saida.splitlines() if ok else []


def listar_forwards() -> list[str]:
    """Retorna as regras de FORWARD da chain ms_forward."""
    ok, saida, _ = rodar(
        "nft list chain ip netforge ms_forward 2>/dev/null",
        silencioso=True,
    )
    if not ok or not saida:
        return []
    return [l.strip() for l in saida.splitlines() if "accept" in l or "drop" in l]