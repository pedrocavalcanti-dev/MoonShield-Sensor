"""
firewall/nucleo/conversor.py
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

    # 1. Interface (Protegido contra ANY maiúsculo)
    iface      = str(regra.get("iface") or "any").strip()
    iface_nome = im.get(iface, iface if iface.lower() != "any" else "")
    if iface_nome:
        direcao = "iifname" if regra.get("dir", "in") == "in" else "oifname"
        partes.append(f'{direcao} "{iface_nome}"')

    # 2. IP origem (Protegido contra ANY maiúsculo)
    src = str(regra.get("src") or "any").strip()
    if src and src.lower() != "any":
        partes.append(f"ip saddr {src}")

    # 3. IP destino (Protegido contra ANY maiúsculo)
    dst = str(regra.get("dst") or "any").strip()
    if dst and dst.lower() != "any":
        partes.append(f"ip daddr {dst}")

    # 4 e 5. Protocolo e Porta (Convertidos para minúsculo na marra)
    proto = str(regra.get("proto") or "any").strip().lower()
    port  = str(regra.get("port") or "any").strip().lower()

    if proto == "icmp":
        partes.append("ip protocol icmp")
    elif proto in ("tcp", "udp"):
        if port and port != "any":
            # Tem protocolo e tem porta específica (ex: tcp dport 80)
            if "-" in port:
                a, b = port.split("-", 1)
                partes.append(f"{proto} dport {a.strip()}-{b.strip()}")
            else:
                partes.append(f"{proto} dport {port}")
        else:
            # Tem protocolo TCP/UDP, mas a porta é ANY (todas as portas)
            partes.append(f"meta l4proto {proto}")
    elif proto not in ("any", ""):
        # Fallback para outros protocolos sem porta
        partes.append(f"ip protocol {proto}")

    # 6. Ação
    if str(regra.get("action")).lower() == "allow":
        partes.append("accept")
    else:
        partes.append("drop")

    return " ".join(partes)


def preview_regra(regra: dict, iface_map: dict | None = None) -> str:
    im    = {**IFACE_MAP_DEFAULT, **(iface_map or {})}
    iface = str(regra.get("iface") or "any").strip()
    nome  = im.get(iface, iface if iface.lower() != "any" else "any")
    
    proto = str(regra.get("proto") or "any").strip().upper()
    port  = str(regra.get("port") or "any").strip().upper()
    acao  = "ACCEPT" if str(regra.get("action")).lower() == "allow" else "DROP"
    
    proto_port = f"{proto}:{port}" if port != "ANY" else proto
    partes = [nome, proto_port, acao]
    
    src = str(regra.get("src") or "any").strip()
    if src and src.lower() != "any":
        partes.insert(0, f"src:{src}")
        
    return "  ".join(partes)


def gerar_script_nft(rules: list[dict], iface_map: dict | None = None) -> str:
    from datetime import datetime

    regras_ativas = sorted(
        [r for r in rules if r.get("enabled", True)],
        key=lambda x: x.get("priority", 500),
    )

    linhas = [
        f"# MoonShield — Regras sincronizadas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total: {len(regras_ativas)} regras ativas",
        "",
        "add table inet moonshield",
        "add chain inet moonshield ms_rules",
        "",
        "flush chain inet moonshield ms_rules",
        "",
    ]

    for r in regras_ativas:
        expr = regra_para_nft_inline(r, iface_map)
        if expr:
            linhas.append(f"add rule inet moonshield ms_rules {expr}")

    linhas.append("")
    return "\n".join(linhas)


def validar_iface_map(iface_map: dict) -> list[str]:
    import os
    avisos = []
    for logico, real in iface_map.items():
        if not real or logico.lower() == "any":
            continue
        if not os.path.exists(f"/sys/class/net/{real}"):
            avisos.append(
                f"Interface '{real}' (mapeada de '{logico}') não encontrada no sistema"
            )
    return avisos