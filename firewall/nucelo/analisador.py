"""
firewall/nucleo/analisador.py
──────────────────────────────────────────────────────────────────────
Parseia linhas de log do kernel geradas pelo nftables LOG.

Formato de entrada (journald):
  kernel: MS-FWD: IN=enp0s3 OUT=enp0s8 SRC=45.33.32.156
          DST=192.168.1.10 LEN=60 TTL=64 PROTO=TCP SPT=54321
          DPT=22 WINDOW=64240 SYN URGP=0

Retorna dict estruturado pronto para enviar ao MoonShield.
──────────────────────────────────────────────────────────────────────
"""

import re
from nucleo.utilitarios import agora

# ══════════════════════════════════════════════════════════════════════════════
# VERSÃO
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_PARSER = "2.0"

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

# v2: reconhece todos os prefixos MS-, não só MS-FWD
PREFIXOS_RECONHECIDOS = {"MS-FWD", "MS-INPUT", "MS-DROP", "MS-OUT", "MS-REJ"}
PREFIXO_FILTRO        = "MS-"   # filtro rápido antes do parse completo

_RE_CAMPO   = re.compile(r'(\w+)=(\S+)')
_RE_PREFIXO = re.compile(r'(MS-[A-Z]+)')

# Flags TCP que aparecem como palavras soltas (sem KEY=VALUE)
_FLAGS_TCP = {"SYN", "ACK", "FIN", "RST", "URG", "PSH", "ECE", "CWR"}

# Mapa de prefixo → (acao, chain)
_MAPA_PREFIXO = {
    "MS-FWD":   ("LOG",    "FORWARD"),
    "MS-DROP":  ("DROP",   "INPUT"),
    "MS-INPUT": ("LOG",    "INPUT"),
    "MS-OUT":   ("LOG",    "OUTPUT"),
    "MS-REJ":   ("REJECT", "INPUT"),
}

# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def parsear_linha(linha: str) -> dict | None:
    """
    Recebe linha raw do journald e retorna dict estruturado.
    Retorna None se a linha não for do MoonShield ou não puder ser parseada.

    v2: reconhece MS-FWD, MS-INPUT, MS-DROP, MS-OUT e MS-REJ.
    """
    if PREFIXO_FILTRO not in linha:
        return None
    try:
        return _extrair_campos(linha)
    except Exception:
        return None

# ══════════════════════════════════════════════════════════════════════════════
# EXTRAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _extrair_campos(linha: str) -> dict | None:
    """Extrai todos os campos da linha do kernel."""

    match = _RE_PREFIXO.search(linha)
    if not match:
        return None

    prefixo = match.group(1)

    # v2: ignora prefixos desconhecidos silenciosamente
    if prefixo not in _MAPA_PREFIXO:
        return None

    acao, chain = _MAPA_PREFIXO[prefixo]

    campos = dict(_RE_CAMPO.findall(linha))

    src_ip = campos.get("SRC", "")
    dst_ip = campos.get("DST", "")
    proto  = campos.get("PROTO", "").upper()

    if not src_ip or not dst_ip:
        return None

    return {
        "timestamp":      agora(),
        "prefixo":        prefixo,
        "acao":           acao,
        "chain":          chain,
        "proto":          proto,
        "src_ip":         src_ip,
        "src_port":       _int_ou_none(campos.get("SPT")),
        "dst_ip":         dst_ip,
        "dst_port":       _int_ou_none(campos.get("DPT")),
        "iface_entrada":  campos.get("IN",  ""),
        "iface_saida":    campos.get("OUT", ""),
        "tamanho":        _int_ou_none(campos.get("LEN")),
        "ttl":            _int_ou_none(campos.get("TTL")),
        "flags_tcp":      _extrair_flags(linha),
        "window":         _int_ou_none(campos.get("WINDOW")),
        "versao_parser":  VERSAO_PARSER,
    }


def _int_ou_none(valor: str | None) -> int | None:
    if not valor:
        return None
    try:
        return int(valor)
    except (ValueError, TypeError):
        return None


def _extrair_flags(linha: str) -> str:
    tokens = set(linha.split())
    flags  = sorted(_FLAGS_TCP & tokens)
    return ",".join(flags) if flags else ""