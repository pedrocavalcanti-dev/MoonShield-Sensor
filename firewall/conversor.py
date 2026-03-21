"""
firewall/conversor.py
──────────────────────────────────────────────────────────────────────
Converte dicts de regras do Django/MoonShield em comandos nft.
──────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

IFACE_MAP_DEFAULT = {
    "WAN": "eth0",
    "LAN": "eth1",
    "VPN": "tun0",
    "any": "",
}


def regra_para_nft_inline(regra: dict, iface_map: dict | None = None) -> str | None:
    im     = {**IFACE_MAP_DEFAULT, **(iface_map or {})}
    partes = []

    iface      = regra.get("iface", "any")
    iface_nome = im.get(iface, "")
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


def gerar_script_nft(rules: list[dict], iface_map: dict | None = None) -> str:
    from datetime import datetime

    linhas = [
        f"# MoonShield — Regras sincronizadas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total: {len(rules)} regras",
        "",
        "table inet moonshield {",
        "",
        "    chain ms_forward {",
        "        type filter hook forward priority 0; policy accept;",
        "        jump ms_emergency",
        "        jump ms_rules",
        '        log prefix "MS-FWD: " flags all',
        "    }",
        "",
        "    chain ms_emergency {",
        "    }",
        "",
        "    chain ms_rules {",
        "    }",
        "",
        "}",
        "",
        "flush chain inet moonshield ms_rules",
        "",
    ]

    regras_ativas = sorted(
        [r for r in rules if r.get("enabled", True)],
        key=lambda x: x.get("priority", 500),
    )

    for r in regras_ativas:
        expr = regra_para_nft_inline(r, iface_map)
        if expr:
            desc = r.get("desc", "")
            prio = r.get("priority", "?")
            linhas.append(f'add rule inet moonshield ms_rules {expr}  # [{prio}] {desc}')

    linhas.append("")
    return "\n".join(linhas)


def validar_iface_map(iface_map: dict) -> list[str]:
    import os
    avisos = []
    for logico, real in iface_map.items():
        if not real or logico == "any":
            continue
        if not os.path.exists(f"/sys/class/net/{real}"):
            avisos.append(f"Interface '{real}' (mapeada de '{logico}') não encontrada no sistema")
    return avisos