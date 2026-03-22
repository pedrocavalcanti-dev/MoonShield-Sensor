"""
firewall/nucleo/conversor.py
──────────────────────────────────────────────────────────────────────
Converte dicts de regras do Django/MoonShield em comandos nft.
──────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

# Default usado apenas quando nenhum iface_map é passado.
IFACE_MAP_DEFAULT = {
    "WAN": "eth0",
    "LAN": "eth1",
    "VPN": "tun0",
    "any": "",
}


def regra_para_nft_inline(regra: dict, iface_map: dict | None = None) -> str | None:
    """Gera expressão nft de uma regra. Retorna None se inválida."""
    im     = {**IFACE_MAP_DEFAULT, **(iface_map or {})}
    partes = []

    iface      = regra.get("iface", "any")
    iface_nome = im.get(iface, iface if iface != "any" else "")
    if iface_nome:
        direcao = "iifname" if regra.get("dir", "in") == "in" else "oifname"
        partes.append(f'{direcao} "{iface_nome}"')

    proto = (regra.get("proto") or "any").lower()
    if proto not in ("any", ""):
        partes.append(proto)

    src = (regra.get("src") or "any").strip()
    if src and src != "any":
        partes.append(f"ip saddr {src}")

    dst = (regra.get("dst") or "any").strip()
    if dst and dst != "any":
        partes.append(f"ip daddr {dst}")

    port = str(regra.get("port") or "any").strip()
    if port and port != "any" and proto in ("tcp", "udp"):
        if "-" in port:
            a, b = port.split("-", 1)
            partes.append(f"dport {a.strip()}-{b.strip()}")
        else:
            partes.append(f"dport {port}")

    partes.append("accept" if regra.get("action") == "allow" else "drop")
    return " ".join(partes)


def preview_regra(regra: dict, iface_map: dict | None = None) -> str:
    """
    Versão legível para humanos — usada na coluna 'Preview nft' do painel.
    ex: enp0s3  TCP:22  DROP
        any  UDP:53  ACCEPT
    """
    im    = {**IFACE_MAP_DEFAULT, **(iface_map or {})}
    iface = regra.get("iface", "any")
    nome  = im.get(iface, iface if iface != "any" else "any")

    proto = (regra.get("proto") or "any").upper()
    port  = str(regra.get("port") or "any").strip()
    acao  = "ACCEPT" if regra.get("action") == "allow" else "DROP"

    proto_port = f"{proto}:{port}" if port != "any" else proto

    partes = [nome, proto_port, acao]

    src = (regra.get("src") or "any").strip()
    if src and src != "any":
        partes.insert(0, f"src:{src}")

    return "  ".join(partes)


def gerar_script_nft(rules: list[dict], iface_map: dict | None = None) -> str:
    """
    Gera script nft que:
    1. Garante que a tabela e chains existam (add — não falha se já existir)
    2. Faz flush apenas na chain ms_rules
    3. Reinserere todas as regras em ordem de prioridade

    Nunca usa 'table { }' pois recriar uma tabela existente causa erro no nft.
    """
    from datetime import datetime

    regras_ativas = sorted(
        [r for r in rules if r.get("enabled", True)],
        key=lambda x: x.get("priority", 500),
    )

    linhas = [
        f"# MoonShield — Regras sincronizadas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total: {len(regras_ativas)} regras ativas",
        "",
        # Garante existência da tabela e chains sem falhar se já existirem
        "add table inet moonshield",
        "",
        "add chain inet moonshield ms_emergency { type filter hook input priority -10; policy accept; }",
        "add chain inet moonshield ms_rules",
        "add chain inet moonshield ms_input { type filter hook input priority 0; policy accept; }",
        "add chain inet moonshield ms_forward { type filter hook forward priority 0; policy accept; }",
        "",
        # Limpa só as regras — não toca na estrutura
        "flush chain inet moonshield ms_rules",
        "",
    ]

    for r in regras_ativas:
        expr = regra_para_nft_inline(r, iface_map)
        if expr:
            desc = r.get("desc", "")
            prio = r.get("priority", "?")
            linhas.append(f"add rule inet moonshield ms_rules {expr}  # [{prio}] {desc}")

    linhas.append("")
    return "\n".join(linhas)


def validar_iface_map(iface_map: dict) -> list[str]:
    """
    Valida se as interfaces mapeadas existem no sistema.
    Só avisa quando o valor não está vazio e a interface não existe.
    """
    import os
    avisos = []
    for logico, real in iface_map.items():
        if not real or logico == "any":
            continue
        if not os.path.exists(f"/sys/class/net/{real}"):
            avisos.append(
                f"Interface '{real}' (mapeada de '{logico}') não encontrada no sistema"
            )
    return avisos