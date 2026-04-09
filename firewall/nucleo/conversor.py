"""
firewall/nucleo/conversor.py
──────────────────────────────────────────────────────────────────────
Converte dicts de regras do Django/MoonShield em comandos nft.

v2 — correcoes e melhorias:
  - IFACE_MAP_DEFAULT removido (eth0/eth1 nunca existem no lab).
    O mapa agora e carregado do config.json do sensor automaticamente
    via _carregar_iface_map(), com fallback para deteccao automatica
    das interfaces reais do sistema operacional.
  - regra_para_nft_inline() nunca retorna None — retorna string vazia
    em casos invalidos, com log de aviso.
  - Suporte a proto "any" gera regra sem filtro de protocolo (correto).
  - Suporte a action "block"/"drop"/"deny" todos mapeiam para drop.
  - Suporte a action "allow"/"accept"/"permit" todos mapeiam para accept.
  - iface_nome vazio (any) nao gera clausula iifname — correto.
  - gerar_script_nft() loga cada regra ignorada para facilitar debug.
  - Nova funcao: diagnosticar_regra() — mostra passo a passo o que
    sera gerado para uma regra, util para depuracao via CLI.
──────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Caminho padrao do config do sensor
_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config.json"

# Cache do iface_map carregado do config
_iface_map_cache: dict | None = None


# ══════════════════════════════════════════════════════════════════════════════
# IFACE MAP — carrega do config.json, com fallback para deteccao automatica
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_interfaces_sistema() -> dict[str, str]:
    """
    Detecta interfaces reais do sistema via /sys/class/net.
    Retorna mapa logico→real baseado na ordem das interfaces
    (primeira nao-loopback = WAN, segunda = LAN, etc.)
    Usado apenas como ultimo fallback.
    """
    try:
        ifaces = [
            nome for nome in sorted(os.listdir("/sys/class/net/"))
            if nome != "lo"
        ]
        mapa = {}
        logicos = ["WAN", "LAN", "VPN", "MGMT"]
        for i, iface in enumerate(ifaces):
            if i < len(logicos):
                mapa[logicos[i]] = iface
            # Tambem mapeia raw→raw para interfaces nomeadas diretamente
            mapa[iface] = iface
        return mapa
    except Exception:
        return {}


def _carregar_iface_map() -> dict:
    """
    Carrega iface_map do config.json do sensor.
    Cacheia o resultado para nao ler o arquivo a cada regra.
    Fallback: deteccao automatica das interfaces do sistema.
    """
    global _iface_map_cache
    if _iface_map_cache is not None:
        return _iface_map_cache

    # Tenta ler do config.json
    try:
        if _CONFIG_PATH.exists():
            with open(_CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
            iface_map = cfg.get("iface_map", {})
            if iface_map:
                # Garante que "any" nao esta mapeado para nada util
                iface_map.pop("any", None)
                _iface_map_cache = iface_map
                logger.debug(f"[conversor] iface_map carregado do config: {iface_map}")
                return _iface_map_cache
    except Exception as e:
        logger.warning(f"[conversor] Falha ao ler config.json: {e}")

    # Fallback: detecta do sistema
    detectado = _detectar_interfaces_sistema()
    logger.warning(f"[conversor] iface_map nao encontrado no config — usando deteccao automatica: {detectado}")
    _iface_map_cache = detectado
    return _iface_map_cache


def _resolver_iface(iface_logica: str, iface_map_externo: dict | None) -> str:
    """
    Resolve nome logico (WAN, LAN, VPN) para nome real (enp0s8, enp0s9...).

    Prioridade:
      1. iface_map_externo (enviado pelo Django na chamada)  — se nao vazio
      2. iface_map do config.json do sensor
      3. Deteccao automatica do sistema
      4. Usa o valor raw (pode ser ja o nome real, ex: "enp0s9")

    Retorna string vazia se iface for "any" ou equivalente.
    """
    if not iface_logica or iface_logica.lower() in ("any", ""):
        return ""

    # Mapa base: config do sensor
    mapa_base = _carregar_iface_map()

    # Mapa externo sobrepoe o base (mas so se nao estiver vazio)
    mapa = {**mapa_base, **(iface_map_externo or {})}
    mapa.pop("any", None)

    # Resolve
    resolvido = mapa.get(iface_logica, iface_logica)
    return resolvido if resolvido and resolvido.lower() != "any" else ""


def _normalizar_acao(action: str) -> str:
    """
    Normaliza a acao da regra para 'accept' ou 'drop'.
    Aceita: allow, accept, permit → accept
            deny, drop, block, reject → drop
    """
    a = str(action or "deny").strip().lower()
    if a in ("allow", "accept", "permit"):
        return "accept"
    return "drop"


def _normalizar_proto(proto: str) -> str:
    """Normaliza protocolo para minusculo. Retorna 'any' se vazio."""
    p = str(proto or "any").strip().lower()
    return p if p else "any"


def _normalizar_port(port: str) -> str:
    """Normaliza porta para minusculo. Retorna 'any' se vazio."""
    p = str(port or "any").strip().lower()
    return p if p else "any"


# ══════════════════════════════════════════════════════════════════════════════
# CONVERSAO PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def regra_para_nft_inline(regra: dict, iface_map: dict | None = None) -> str:
    """
    Converte um dict de regra em expressao nft inline.

    Retorna string pronta para usar em:
      add rule inet moonshield ms_rules <RETORNO>

    Retorna string vazia "" se a regra for invalida (nunca None).
    """
    partes: list[str] = []

    # ── 1. Interface ──────────────────────────────────────────────────────────
    iface_logica = str(regra.get("iface") or "any").strip()
    iface_nome   = _resolver_iface(iface_logica, iface_map)

    if iface_nome:
        direcao = "iifname" if str(regra.get("dir", "in")).strip().lower() == "in" else "oifname"
        partes.append(f'{direcao} "{iface_nome}"')

    # ── 2. IP de origem ───────────────────────────────────────────────────────
    src = str(regra.get("src") or "any").strip()
    if src and src.lower() != "any":
        # Valida formato basico (IP ou CIDR)
        if _parece_ip_ou_cidr(src):
            partes.append(f"ip saddr {src}")
        else:
            logger.warning(f"[conversor] src invalido ignorado: '{src}'")

    # ── 3. IP de destino ──────────────────────────────────────────────────────
    dst = str(regra.get("dst") or "any").strip()
    if dst and dst.lower() != "any":
        if _parece_ip_ou_cidr(dst):
            partes.append(f"ip daddr {dst}")
        else:
            logger.warning(f"[conversor] dst invalido ignorado: '{dst}'")

    # ── 4+5. Protocolo e Porta ────────────────────────────────────────────────
    proto = _normalizar_proto(regra.get("proto", "any"))
    port  = _normalizar_port(regra.get("port",  "any"))

    if proto == "icmp":
        partes.append("ip protocol icmp")

    elif proto in ("tcp", "udp"):
        if port and port != "any":
            # Porta especifica ou range (ex: 80 ou 8000-9000)
            port_limpa = port.replace(" ", "")
            if "-" in port_limpa:
                a, b = port_limpa.split("-", 1)
                partes.append(f"{proto} dport {a.strip()}-{b.strip()}")
            else:
                partes.append(f"{proto} dport {port_limpa}")
        else:
            # Protocolo sem porta especifica — qualquer porta TCP/UDP
            partes.append(f"meta l4proto {proto}")

    elif proto not in ("any", ""):
        # Protocolo desconhecido — tenta ip protocol generico
        partes.append(f"ip protocol {proto}")

    # proto == "any" → sem clausula de protocolo (pega tudo)

    # ── 6. Acao ───────────────────────────────────────────────────────────────
    partes.append(_normalizar_acao(regra.get("action", "deny")))

    resultado = " ".join(partes)

    if not resultado or resultado in ("accept", "drop"):
        # Regra sem nenhum criterio de matching — muito permissiva, loga aviso
        logger.warning(
            f"[conversor] Regra sem criterios de matching gerada: '{resultado}' "
            f"— regra: {regra}"
        )

    return resultado


# ══════════════════════════════════════════════════════════════════════════════
# PREVIEW LEGIVEL
# ══════════════════════════════════════════════════════════════════════════════

def preview_regra(regra: dict, iface_map: dict | None = None) -> str:
    """Retorna string legivel para exibicao no painel/TUI."""
    iface_logica = str(regra.get("iface") or "any").strip()
    iface_nome   = _resolver_iface(iface_logica, iface_map) or "any"

    proto = _normalizar_proto(regra.get("proto", "any")).upper()
    port  = _normalizar_port(regra.get("port",  "any")).upper()
    acao  = "ACCEPT" if _normalizar_acao(regra.get("action", "deny")) == "accept" else "DROP"

    proto_port = f"{proto}:{port}" if port != "ANY" else proto
    partes = [iface_nome, proto_port, acao]

    src = str(regra.get("src") or "any").strip()
    if src and src.lower() != "any":
        partes.insert(0, f"src:{src}")

    dst = str(regra.get("dst") or "any").strip()
    if dst and dst.lower() != "any":
        partes.insert(1, f"dst:{dst}")

    return "  ".join(partes)


# ══════════════════════════════════════════════════════════════════════════════
# GERACAO DO SCRIPT NFT COMPLETO
# ══════════════════════════════════════════════════════════════════════════════

def gerar_script_nft(rules: list[dict], iface_map: dict | None = None) -> str:
    """
    Gera script nft completo para aplicar via nft -f.

    O script faz flush da chain ms_rules e reescreve todas as regras
    ativas ordenadas por prioridade.

    iface_map externo (enviado pelo Django) sobrepoe o do config.json.
    Se vazio, usa automaticamente o config.json do sensor.
    """
    from datetime import datetime

    regras_ativas = sorted(
        [r for r in rules if r.get("enabled", True)],
        key=lambda x: x.get("priority", 500),
    )

    linhas = [
        f"# MoonShield — Regras sincronizadas em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# Total: {len(regras_ativas)} regras ativas",
        f"# iface_map externo: {iface_map or '(vazio — usando config.json)'}",
        "",
        "add table inet moonshield",
        "add chain inet moonshield ms_rules",
        "",
        "flush chain inet moonshield ms_rules",
        "",
    ]

    aplicadas = 0
    ignoradas = 0

    for r in regras_ativas:
        expr = regra_para_nft_inline(r, iface_map)
        if expr:
            desc = r.get("desc", "") or ""
            comentario = f"  # [{r.get('priority', '?')}] {desc[:60]}" if desc else f"  # [{r.get('priority', '?')}]"
            linhas.append(f"add rule inet moonshield ms_rules {expr}{comentario}")
            aplicadas += 1
        else:
            logger.warning(f"[conversor] Regra ignorada (expr vazia): {r}")
            ignoradas += 1

    if ignoradas:
        linhas.append(f"\n# AVISO: {ignoradas} regra(s) ignorada(s) — verifique os logs do sensor")

    linhas.append("")
    logger.info(f"[conversor] Script gerado: {aplicadas} regras aplicadas, {ignoradas} ignoradas")
    return "\n".join(linhas)


# ══════════════════════════════════════════════════════════════════════════════
# DIAGNOSTICO — util para debug via CLI
# ══════════════════════════════════════════════════════════════════════════════

def diagnosticar_regra(regra: dict, iface_map: dict | None = None) -> str:
    """
    Mostra passo a passo o que sera gerado para uma regra.
    Util para rodar no terminal e depurar problemas de conversao.

    Exemplo de uso:
        from firewall.nucleo.conversor import diagnosticar_regra
        print(diagnosticar_regra({"action": "deny", "iface": "LAN", ...}))
    """
    linhas = ["=" * 60, "DIAGNOSTICO DA REGRA", "=" * 60]

    iface_logica = str(regra.get("iface") or "any").strip()
    iface_nome   = _resolver_iface(iface_logica, iface_map)
    mapa_base    = _carregar_iface_map()
    mapa_final   = {**mapa_base, **(iface_map or {})}

    linhas.append(f"iface logica   : {iface_logica!r}")
    linhas.append(f"iface_map base : {mapa_base}")
    linhas.append(f"iface_map extra: {iface_map or {}}")
    linhas.append(f"iface resolvida: {iface_nome!r} {'(sem clausula iifname)' if not iface_nome else ''}")
    linhas.append(f"dir            : {regra.get('dir', 'in')!r} → {'iifname' if regra.get('dir','in')=='in' else 'oifname'}")
    linhas.append(f"src            : {regra.get('src', 'any')!r}")
    linhas.append(f"dst            : {regra.get('dst', 'any')!r}")
    linhas.append(f"proto          : {regra.get('proto', 'any')!r} → {_normalizar_proto(regra.get('proto','any'))!r}")
    linhas.append(f"port           : {regra.get('port', 'any')!r}")
    linhas.append(f"action         : {regra.get('action', 'deny')!r} → {_normalizar_acao(regra.get('action','deny'))!r}")
    linhas.append(f"enabled        : {regra.get('enabled', True)}")
    linhas.append("-" * 60)

    expr = regra_para_nft_inline(regra, iface_map)
    linhas.append(f"EXPRESSAO GERADA:")
    linhas.append(f"  add rule inet moonshield ms_rules {expr}")
    linhas.append("=" * 60)

    return "\n".join(linhas)


# ══════════════════════════════════════════════════════════════════════════════
# VALIDACAO DO IFACE MAP
# ══════════════════════════════════════════════════════════════════════════════

def validar_iface_map(iface_map: dict) -> list[str]:
    """
    Valida se as interfaces do mapa existem no sistema.
    Retorna lista de avisos (vazia se tudo ok).
    """
    avisos = []
    for logico, real in iface_map.items():
        if not real or logico.lower() == "any":
            continue
        if not os.path.exists(f"/sys/class/net/{real}"):
            avisos.append(
                f"Interface '{real}' (mapeada de '{logico}') nao encontrada no sistema"
            )
    return avisos


def recarregar_config():
    """Forca recarga do config.json na proxima chamada. Util apos salvar novo config."""
    global _iface_map_cache
    _iface_map_cache = None


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════════════════

def _parece_ip_ou_cidr(valor: str) -> bool:
    """Validacao basica: aceita IPs (v4) e CIDRs. Rejeita strings claramente invalidas."""
    import re
    # Aceita: 1.2.3.4, 1.2.3.4/24, 10.0.0.0/8
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', valor))