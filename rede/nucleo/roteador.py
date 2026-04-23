"""
rede/nucleo/roteador.py
──────────────────────────────────────────────────────────────────────
Configura roteamento, NAT e ip_forward.

Backend automático:
  - Na inicialização detecta o que está disponível no sistema:
      1. nftables (nft disponível e kernel >= 5.2) → usa tabela ip netforge
      2. iptables disponível                        → usa iptables diretamente
      3. Nenhum disponível                          → retorna erro claro

  - Toda a lógica pública (aplicar_masquerade, aplicar_forward_*, etc.)
    funciona igual independente do backend — o caller não precisa saber qual.

  - A tabela nftables fica em "ip netforge" (isolada do MoonShield que
    usa "inet moonshield"). Nunca há conflito entre os dois sistemas.
──────────────────────────────────────────────────────────────────────
"""

import os
import platform
from .utilitarios import rodar, interface_existe


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE BACKEND
# ══════════════════════════════════════════════════════════════════════════════

def _versao_kernel() -> tuple[int, int]:
    """Retorna (major, minor) do kernel Linux."""
    try:
        release = platform.release().split("-")[0]
        partes  = release.split(".")
        return int(partes[0]), int(partes[1])
    except Exception:
        return 0, 0


def _nft_disponivel() -> bool:
    ok, _, _ = rodar(["which", "nft"], silencioso=True)
    return ok


def _iptables_disponivel() -> bool:
    ok, _, _ = rodar(["which", "iptables"], silencioso=True)
    return ok


def detectar_backend() -> str:
    if _nft_disponivel():
        major, minor = _versao_kernel()
        if major > 5 or (major == 5 and minor >= 2):
            return "nftables"
        ok, _, _ = rodar(
            ["nft", "add", "table", "ip", "_teste_nat_moonshield"],
            silencioso=True,
        )
        if ok:
            rodar(["nft", "delete", "table", "ip", "_teste_nat_moonshield"], silencioso=True)
            return "nftables"

    if _iptables_disponivel():
        return "iptables"

    return "nenhum"


_BACKEND: str = detectar_backend()


def backend_ativo() -> str:
    return _BACKEND


# ══════════════════════════════════════════════════════════════════════════════
# ip_forward
# ══════════════════════════════════════════════════════════════════════════════

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
    ok, val, _ = rodar(["sysctl", "net.ipv4.ip_forward"], silencioso=True)
    if ok and "=" in val:
        return val.split("=")[-1].strip()
    return "?"


def _persistir_sysctl(chave: str, valor: str):
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


# ══════════════════════════════════════════════════════════════════════════════
# ROTA PADRÃO  ← NOVO
# ══════════════════════════════════════════════════════════════════════════════

def aplicar_rota_padrao(gateway: str) -> tuple[bool, str]:
    """
    Define o gateway padrão (rota default).
    Usa 'replace' para não duplicar se já existir.
    """
    from .utilitarios import validar_ip
    if not validar_ip(gateway):
        return False, f"Gateway inválido: '{gateway}'"

    ok, _, err = rodar(["ip", "route", "replace", "default", "via", gateway])
    return (True, "") if ok else (False, f"Erro ao definir rota padrão: {err}")


def remover_rota_padrao() -> tuple[bool, str]:
    """Remove a rota padrão atual, se existir."""
    ok, _, err = rodar(["ip", "route", "del", "default"], silencioso=True)
    return (True, "") if ok else (False, err)


# ══════════════════════════════════════════════════════════════════════════════
# TABELA / CHAINS — nftables
# ══════════════════════════════════════════════════════════════════════════════

def limpar_tabela() -> tuple[bool, str]:
    if _BACKEND == "nftables":
        rodar(["nft", "delete", "table", "ip", "netforge"], silencioso=True)
        return True, ""
    if _BACKEND == "iptables":
        return _iptables_flush()
    return True, ""


def criar_tabela() -> tuple[bool, str]:
    if _BACKEND != "nftables":
        return True, f"backend {_BACKEND} — sem tabela nftables necessária"

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


# ══════════════════════════════════════════════════════════════════════════════
# NAT / MASQUERADE
# ══════════════════════════════════════════════════════════════════════════════

def aplicar_masquerade(wan: str) -> tuple[bool, str]:
    if not interface_existe(wan):
        return False, f"Interface '{wan}' não encontrada."

    if _BACKEND == "nftables":
        ok, _, err = rodar([
            "nft", "add", "rule", "ip", "netforge", "ms_nat_post",
            "oifname", wan, "masquerade",
        ])
        return (True, "") if ok else (False, f"Erro MASQUERADE nft em {wan}: {err}")

    if _BACKEND == "iptables":
        ok, _, err = rodar([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", wan, "-j", "MASQUERADE",
        ])
        return (True, "") if ok else (False, f"Erro MASQUERADE iptables em {wan}: {err}")

    return False, "Nenhum backend de firewall disponível."


# ══════════════════════════════════════════════════════════════════════════════
# FORWARD
# ══════════════════════════════════════════════════════════════════════════════

def aplicar_forward_entre_interfaces(origem: str, destino: str) -> tuple[bool, str]:
    if not interface_existe(origem):
        return False, f"Interface '{origem}' não encontrada."
    if not interface_existe(destino):
        return False, f"Interface '{destino}' não encontrada."

    if _BACKEND == "nftables":
        return _nft_forward_bidirecional(origem, destino)
    if _BACKEND == "iptables":
        return _ipt_forward_bidirecional(origem, destino)
    return False, "Nenhum backend disponível."


def aplicar_forward_interface_wan(lan: str, wan: str) -> tuple[bool, str]:
    if not interface_existe(lan):
        return False, f"Interface LAN '{lan}' não encontrada."
    if not interface_existe(wan):
        return False, f"Interface WAN '{wan}' não encontrada."

    if _BACKEND == "nftables":
        return _nft_forward_lan_wan(lan, wan)
    if _BACKEND == "iptables":
        return _ipt_forward_lan_wan(lan, wan)
    return False, "Nenhum backend disponível."


def aplicar_forward_vlan_wan(vlan_iface: str, wan: str) -> tuple[bool, str]:
    return aplicar_forward_interface_wan(vlan_iface, wan)


def aplicar_forward_entre_vlans(ifaces: list[str]) -> tuple[bool, str]:
    erros = []
    for i, a in enumerate(ifaces):
        for b in ifaces[i + 1:]:
            ok, err = aplicar_forward_entre_interfaces(a, b)
            if not ok:
                erros.append(err)
    return (False, " | ".join(erros)) if erros else (True, "")


# ══════════════════════════════════════════════════════════════════════════════
# IMPLEMENTAÇÕES nftables
# ══════════════════════════════════════════════════════════════════════════════

def _nft_forward_bidirecional(a: str, b: str) -> tuple[bool, str]:
    erros = []
    for src, dst in [(a, b), (b, a)]:
        ok, _, err = rodar([
            "nft", "add", "rule", "ip", "netforge", "ms_forward",
            "iifname", src, "oifname", dst, "accept",
        ])
        if not ok:
            erros.append(f"{src}→{dst}: {err}")
    return (False, " | ".join(erros)) if erros else (True, "")


def _nft_forward_lan_wan(lan: str, wan: str) -> tuple[bool, str]:
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
    return (False, " | ".join(erros)) if erros else (True, "")


# ══════════════════════════════════════════════════════════════════════════════
# IMPLEMENTAÇÕES iptables
# ══════════════════════════════════════════════════════════════════════════════

def _iptables_flush() -> tuple[bool, str]:
    rodar(["iptables", "-t", "nat",    "-F", "POSTROUTING"], silencioso=True)
    rodar(["iptables", "-t", "filter", "-F", "FORWARD"],     silencioso=True)
    return True, ""


def _ipt_forward_bidirecional(a: str, b: str) -> tuple[bool, str]:
    erros = []
    for src, dst in [(a, b), (b, a)]:
        ok, _, err = rodar([
            "iptables", "-A", "FORWARD",
            "-i", src, "-o", dst, "-j", "ACCEPT",
        ])
        if not ok:
            erros.append(f"{src}→{dst}: {err}")
    return (False, " | ".join(erros)) if erros else (True, "")


def _ipt_forward_lan_wan(lan: str, wan: str) -> tuple[bool, str]:
    erros = []
    ok1, _, e1 = rodar([
        "iptables", "-A", "FORWARD",
        "-i", lan, "-o", wan, "-j", "ACCEPT",
    ])
    if not ok1:
        erros.append(e1)
    ok2, _, e2 = rodar([
        "iptables", "-A", "FORWARD",
        "-i", wan, "-o", lan,
        "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT",
    ])
    if not ok2:
        erros.append(e2)
    return (False, " | ".join(erros)) if erros else (True, "")


# ══════════════════════════════════════════════════════════════════════════════
# ROTEAMENTO COMPLETO (orquestrador)
# ══════════════════════════════════════════════════════════════════════════════

def aplicar_roteamento_completo(config: dict) -> list[tuple[str, bool, str]]:
    """
    Orquestra toda a configuração de roteamento a partir do dict de config.

    Campos suportados:
      wan_interface   — interface WAN (saída internet)
      gateway         — IP do gateway padrão (ex: 10.53.52.1)  ← NOVO
      trunk_interface — interface trunk para VLANs
      vlans           — lista de {'id': 10, 'nome': 'LAN'}
      rotas_diretas   — lista de {'lan': 'enp0s9', 'wan': 'enp0s3'}

    Retorna lista de (etapa, sucesso, mensagem).
    """
    wan           = config.get("wan_interface", "")
    gateway       = config.get("gateway", "")          # ← NOVO
    trunk         = config.get("trunk_interface", "")
    vlans         = config.get("vlans", [])
    rotas_diretas = config.get("rotas_diretas", [])

    etapas: list[tuple[str, bool, str]] = []

    # 0. Backend
    etapas.append(("Backend firewall", True, _BACKEND))

    # 1. ip_forward
    ok, err = ativar_ip_forward()
    etapas.append(("ip_forward", ok, "Ativado" if ok else err))

    # 2. Rota padrão  ← NOVO
    if gateway:
        ok, err = aplicar_rota_padrao(gateway)
        etapas.append(("Rota padrão", ok, f"via {gateway}" if ok else err))

    # 3. Limpa e recria tabela
    limpar_tabela()
    if _BACKEND == "nftables":
        ok, err = criar_tabela()
        etapas.append(("Tabela netforge", ok, "Criada" if ok else err))
        if not ok:
            return etapas

    # 4. MASQUERADE na WAN principal
    if wan:
        ok, err = aplicar_masquerade(wan)
        etapas.append((f"MASQUERADE ({wan})", ok, "Aplicado" if ok else err))

    # 5. Rotas diretas (sem VLAN)
    for rota in rotas_diretas:
        lan_r = rota.get("lan", "")
        wan_r = rota.get("wan", wan)
        if not lan_r:
            continue
        ok, err = aplicar_forward_interface_wan(lan_r, wan_r)
        etapas.append((f"FORWARD {lan_r}→{wan_r}", ok, "Aplicado" if ok else err))

    # 6. FORWARD VLAN → WAN
    ifaces_vlan = []
    for vlan in vlans:
        vlan_iface = f"{trunk}.{vlan['id']}"
        ifaces_vlan.append(vlan_iface)
        if wan:
            ok, err = aplicar_forward_vlan_wan(vlan_iface, wan)
            etapas.append((f"FORWARD {vlan_iface}↔{wan}", ok, "Aplicado" if ok else err))

    # 7. FORWARD inter-VLAN
    if len(ifaces_vlan) >= 2:
        ok, err = aplicar_forward_entre_vlans(ifaces_vlan)
        etapas.append(("FORWARD inter-VLAN", ok, "Aplicado" if ok else err))

    return etapas


# ══════════════════════════════════════════════════════════════════════════════
# STATUS / LISTAGEM
# ══════════════════════════════════════════════════════════════════════════════

def listar_regras_nat() -> list[str]:
    if _BACKEND == "nftables":
        ok, saida, _ = rodar(
            "nft list chain ip netforge ms_nat_post 2>/dev/null",
            silencioso=True,
        )
        if not ok or not saida:
            return []
        return [l.strip() for l in saida.splitlines() if "masquerade" in l or "snat" in l]

    if _BACKEND == "iptables":
        ok, saida, _ = rodar(
            "iptables -t nat -L POSTROUTING -n -v 2>/dev/null",
            silencioso=True,
        )
        if not ok or not saida:
            return []
        return [l.strip() for l in saida.splitlines() if "MASQUERADE" in l or "SNAT" in l]

    return []


def listar_forwards() -> list[str]:
    if _BACKEND == "nftables":
        ok, saida, _ = rodar(
            "nft list chain ip netforge ms_forward 2>/dev/null",
            silencioso=True,
        )
        if not ok or not saida:
            return []
        return [l.strip() for l in saida.splitlines() if "accept" in l or "drop" in l]

    if _BACKEND == "iptables":
        ok, saida, _ = rodar(
            "iptables -L FORWARD -n -v 2>/dev/null",
            silencioso=True,
        )
        if not ok or not saida:
            return []
        return [l.strip() for l in saida.splitlines() if "ACCEPT" in l or "DROP" in l]

    return []


def listar_rotas() -> list[str]:
    ok, saida, _ = rodar(["ip", "route", "show"], silencioso=True)
    return saida.splitlines() if ok else []