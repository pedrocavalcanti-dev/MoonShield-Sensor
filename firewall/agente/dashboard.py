"""
firewall/agente/dashboard.py
──────────────────────────────────────────────────────────────────────
Painel TUI que substitui o spam de logs do modo --auto.
Redesenha o terminal a cada REFRESH_INTERVAL segundos.
──────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_DASHBOARD = "2.0"
REFRESH_INTERVAL = 5   # segundos

# Cores ANSI
C_OK     = "\033[92m"
C_ERRO   = "\033[91m"
C_AVISO  = "\033[93m"
C_DIM    = "\033[2m"
C_TITULO = "\033[96m"
C_RESET  = "\033[0m"
NEGRITO  = "\033[1m"

_W = 62   # largura interna do painel (sem as bordas)

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO INTERNO
# ══════════════════════════════════════════════════════════════════════════════

_dash_stats: dict = {
    "rodando":   False,
    "refreshes": 0,
}
_dash_lock = threading.Lock()
_thread:    threading.Thread | None = None

# timestamp de quando cada IP foi banido (para "há X min")
_ban_times: dict[str, float] = {}

_inicio_ts: float = 0.0
_cfg_ref:   dict  = {}

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS DE FORMATAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _pad(texto: str, largura: int = _W) -> str:
    """Retorna texto padded para largura, sem contar escapes ANSI."""
    visivel = re.sub(r'\033\[[^m]*m', '', texto)
    espacos = max(0, largura - len(visivel))
    return texto + " " * espacos


def _linha(conteudo: str = "") -> str:
    return f"║  {_pad(conteudo, _W - 2)}║"


def _sep() -> str:
    return "╠" + "═" * (_W + 2) + "╣"


def _topo() -> str:
    return "╔" + "═" * (_W + 2) + "╗"


def _fundo() -> str:
    return "╚" + "═" * (_W + 2) + "╝"


def _ok(txt: str)   -> str: return f"{C_OK}{NEGRITO}{txt}{C_RESET}"
def _err(txt: str)  -> str: return f"{C_ERRO}{NEGRITO}{txt}{C_RESET}"
def _aviso(txt: str) -> str: return f"{C_AVISO}{txt}{C_RESET}"
def _dim(txt: str)  -> str: return f"{C_DIM}{txt}{C_RESET}"
def _titulo(txt: str) -> str: return f"{C_TITULO}{NEGRITO}{txt}{C_RESET}"


def _uptime_str(segundos: int) -> str:
    h = segundos // 3600
    m = (segundos % 3600) // 60
    return f"{h}h{m:02d}m"


def _ha_quanto(ts: float) -> str:
    delta = int(time.time() - ts)
    if delta < 60:   return f"há {delta}s"
    if delta < 3600: return f"há {delta//60}min"
    return f"há {delta//3600}h"


def _agora_str() -> str:
    return datetime.now().strftime("%H:%M:%S")

# ══════════════════════════════════════════════════════════════════════════════
# COLETA DE DADOS DO nft
# ══════════════════════════════════════════════════════════════════════════════

def _regras_chain(chain: str) -> list[str]:
    """Retorna linhas de regras de uma chain (sem handles, sem diretivas)."""
    try:
        r = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", chain],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        linhas = []
        for l in r.stdout.splitlines():
            l = l.strip()
            if not l or "{" in l or "}" in l: continue
            if any(k in l for k in ("hook", "policy", "jump", "log", "type")): continue
            linhas.append(l)
        return linhas
    except Exception:
        return []


def _regras_emergency() -> list[tuple[str, str]]:
    """Retorna lista de (ip, expressão) da chain ms_emergency."""
    try:
        r = subprocess.run(
            ["nft", "-a", "list", "chain", "inet", "moonshield", "ms_emergency"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        resultado = []
        for linha in r.stdout.splitlines():
            linha = linha.strip()
            if not linha or "{" in linha or "}" in linha: continue
            if any(k in linha for k in ("hook", "policy", "jump", "log", "type")): continue
            m = re.search(r"ip saddr (\S+)", linha)
            ip = m.group(1) if m else "?"
            # Registra timestamp se IP ainda não conhecido
            if ip not in _ban_times:
                _ban_times[ip] = time.time()
            resultado.append((ip, linha))
        return resultado
    except Exception:
        return []


def _expr_para_preview(expr: str) -> str:
    iface = re.search(r'iifname "([^"]+)"', expr)
    proto = re.search(r'\b(tcp|udp|icmp)\b', expr)
    port  = re.search(r'dport (\S+)', expr)
    acao  = "DROP" if "drop" in expr else "ACCEPT"
    partes = []
    if iface: partes.append(iface.group(1))
    p = (proto.group(1).upper() if proto else "ANY")
    if port: p += f":{port.group(1)}"
    partes.append(p)
    partes.append(acao)
    return "  ".join(partes)


# ══════════════════════════════════════════════════════════════════════════════
# MONTAGEM DO PAINEL
# ══════════════════════════════════════════════════════════════════════════════

def _montar_painel(cfg: dict, stats_fn: dict, refresh_n: int) -> str:
    agora     = _agora_str()
    sensor    = cfg.get("sensor_nome", "SENSOR")
    moon_url  = cfg.get("Moon_url", "—")
    uptime    = _uptime_str(int(time.time() - _inicio_ts)) if _inicio_ts else "—"

    # Coleta stats de cada módulo
    def _safe(fn_key: str) -> dict:
        try: return stats_fn[fn_key]()
        except Exception: return {}

    mon  = _safe("monitoramento")
    sync = _safe("sincronizador")
    ban  = _safe("autoban")
    agt  = _safe("agente")

    # Online/offline baseado em último envio bem-sucedido
    online = mon.get("enviados", 0) > 0 or sync.get("polls", 0) > 0
    status_moon = _ok("[ONLINE]") if online else _err("[OFFLINE]")

    linhas = []
    linhas.append(_topo())

    # Cabeçalho
    cab = f"{_titulo('MOONSHIELD · FIREWALL SENSOR')}  {_ok(sensor)}  {agora}"
    linhas.append(_linha(cab))
    sub = f"Moon: {_dim(moon_url)}  {status_moon}  Up: {_ok(uptime)}"
    linhas.append(_linha(sub))

    # ── Monitoramento ──
    linhas.append(_sep())
    linhas.append(_linha(_titulo("MONITORAMENTO nftables")))
    vis = mon.get("vistos",   0)
    env = mon.get("enviados", 0)
    err = mon.get("erros",    0)
    ult = mon.get("ultimo",   "—")
    d   = mon.get("drops",    0)
    a   = mon.get("allows",   0)
    linhas.append(_linha(
        f"Vistos: {_ok(str(vis))}   Enviados: {_ok(str(env))}   Erros: {_err(str(err)) if err else _dim('0')}"
    ))
    linhas.append(_linha(
        f"Drops: {_err(str(d))}   Allows: {_ok(str(a))}   Último: {_dim(str(ult))}"
    ))

    # ── Sincronizador ──
    linhas.append(_sep())
    linhas.append(_linha(_titulo("SINCRONIZADOR Django → nft")))
    polls  = sync.get("polls",        0)
    aplics = sync.get("aplicacoes",   0)
    serr   = sync.get("erros",        0)
    skip   = sync.get("sem_mudanca",  0)
    ra     = sync.get("regras_ativas", 0)
    ult_s  = sync.get("ultimo_apply", "—")
    linhas.append(_linha(
        f"Polls: {_ok(str(polls))}   Aplicações: {_ok(str(aplics))}   Erros: {_err(str(serr)) if serr else _dim('0')}   Skip: {_dim(str(skip))}"
    ))
    linhas.append(_linha(
        f"Regras no nft: {_ok(str(ra))}   Último apply: {_dim(str(ult_s))}"
    ))

    # ── Agente HTTP ──
    linhas.append(_sep())
    porta_agt = agt.get("porta", 8765)
    rod_agt   = agt.get("rodando", False)
    agt_status = _ok("[ATIVO]") if rod_agt else _aviso("[INATIVO]")
    linhas.append(_linha(f"{_titulo('AGENTE HTTP')}  :{porta_agt}  {agt_status}"))
    cham  = agt.get("chamadas_total",  0)
    ult_c = agt.get("ultima_chamada",  "—")
    ep    = agt.get("ultimo_endpoint", "—")
    linhas.append(_linha(f"Chamadas: {_ok(str(cham))}   Último: {_dim(str(ult_c))}   {_dim(ep)}"))

    # ── Auto-ban ──
    linhas.append(_sep())
    linhas.append(_linha(_titulo("AUTO-BAN")))
    tb  = ban.get("total_bans", 0)
    ia  = ban.get("ips_ativos", 0)
    uip = ban.get("ultimo_ip",  "—")
    linhas.append(_linha(
        f"Bans sessão: {_err(str(tb)) if tb else _dim('0')}   "
        f"Ativos agora: {_err(str(ia)) if ia else _dim('0')}   "
        f"Último: {_aviso(str(uip))}"
    ))

    # ── Bloqueios ativos (ms_emergency) ──
    linhas.append(_sep())
    linhas.append(_linha(_titulo("BLOQUEIOS ATIVOS (ms_emergency)")))
    emergency = _regras_emergency()
    if emergency:
        for ip, expr in emergency[:5]:
            ha = _ha_quanto(_ban_times.get(ip, time.time()))
            motivo_m = re.search(r'comment "([^"]+)"', expr)
            motivo   = motivo_m.group(1) if motivo_m else "—"
            linhas.append(_linha(f"  {_err(ip)}   {_dim(motivo)}   {_dim(ha)}"))
        if len(emergency) > 5:
            linhas.append(_linha(_dim(f"  (+ {len(emergency)-5} mais)")))
    else:
        linhas.append(_linha(_dim("  (nenhum bloqueio ativo)")))

    # ── Regras ativas (ms_rules) ──
    linhas.append(_sep())
    linhas.append(_linha(_titulo("REGRAS ATIVAS (ms_rules)")))
    regras_ms = _regras_chain("ms_rules")
    if regras_ms:
        for expr in regras_ms[:5]:
            prev = _expr_para_preview(expr)
            # Extrai comentário de descrição se houver
            desc_m = re.search(r'#.*?\](.*)', expr)
            desc   = desc_m.group(1).strip() if desc_m else ""
            linha_r = f"  {_ok(prev)}"
            if desc:
                linha_r += f"   {_dim('— ' + desc[:28])}"
            linhas.append(_linha(linha_r))
        if len(regras_ms) > 5:
            linhas.append(_linha(_dim(f"  (+ {len(regras_ms)-5} mais)")))
    else:
        linhas.append(_linha(_dim("  (nenhuma regra ativa)")))

    # ── Rodapé ──
    linhas.append(_sep())
    rodape = f"[Ctrl+C para parar]{' ' * 20}Refresh #{refresh_n}  {REFRESH_INTERVAL}s"
    linhas.append(_linha(_dim(rodape)))
    linhas.append(_fundo())

    return "\n".join(linhas)


# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def _loop_dashboard(cfg: dict, parar: threading.Event, stats_fn: dict):
    global _inicio_ts
    _inicio_ts = time.time()

    with _dash_lock:
        _dash_stats["rodando"] = True

    while not parar.is_set():
        with _dash_lock:
            _dash_stats["refreshes"] += 1
            n = _dash_stats["refreshes"]

        try:
            painel = _montar_painel(cfg, stats_fn, n)
            os.system("clear")
            print(painel, flush=True)
        except Exception as e:
            print(f"[dashboard erro] {e}")

        for _ in range(REFRESH_INTERVAL * 10):
            if parar.is_set():
                break
            time.sleep(0.1)

    os.system("clear")
    with _dash_lock:
        _dash_stats["rodando"] = False


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def iniciar_dashboard(
    cfg: dict,
    parar: threading.Event,
    stats_fn: dict,
) -> threading.Thread:
    global _thread, _cfg_ref
    _cfg_ref = cfg

    _thread = threading.Thread(
        target=_loop_dashboard,
        args=(cfg, parar, stats_fn),
        name="ms-dashboard",
        daemon=True,
    )
    _thread.start()
    return _thread


def parar_dashboard():
    with _dash_lock:
        _dash_stats["rodando"] = False


def obter_stats() -> dict:
    with _dash_lock:
        return dict(_dash_stats)