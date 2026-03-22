"""
firewall/agente/agente.py
──────────────────────────────────────────────────────────────────────
Servidor HTTP Flask local (porta 8765) — o Django chama diretamente
este servidor em vez de esperar o sensor fazer poll a cada 30s.

v3: usa threading=True no werkzeug para evitar travamento quando
    o dashboard TUI ocupa o loop principal. Cada request roda em
    thread separada — resolve o bug de "request enviado, sem resposta".

Autenticação: header X-MS-TOKEN em todos os endpoints.
──────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request

from nucleo.utilitarios import agora as _agora
from firewall.nucleo.conversor  import gerar_script_nft, preview_regra
from firewall.nucleo.instalador import obter_status as _status_nft
from firewall.monitoramento.autoban       import obter_stats as _stats_autoban
from firewall.monitoramento.sincronizador import obter_stats as _stats_sync
from firewall.monitoramento.monitoramento import obter_stats as _stats_mon

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_AGENTE = "3.0"
PORTA_PADRAO  = 8765

TMP_APPLY = "/tmp/ms_agente_apply.nft"

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO INTERNO
# ══════════════════════════════════════════════════════════════════════════════

_agente_stats: dict = {
    "rodando":         False,
    "porta":           PORTA_PADRAO,
    "chamadas_total":  0,
    "ultima_chamada":  "—",
    "ultimo_endpoint": "—",
    "erros":           0,
    "iniciado_em":     "—",
}
_agente_lock = threading.Lock()
_cfg_ref:  dict = {}

# Guarda timers de expiração de bloqueios: ip → threading.Timer
_timers_expiracao: dict[str, threading.Timer] = {}
_inicio_ts: float = 0.0

# ══════════════════════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)
app.logger.disabled = True

import logging
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


# ── Decorator de autenticação ────────────────────────────────────────────────

def _requer_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-MS-TOKEN", "")
        if token != _cfg_ref.get("token", ""):
            return jsonify({"ok": False, "error": "Token inválido"}), 403
        with _agente_lock:
            _agente_stats["chamadas_total"] += 1
            _agente_stats["ultima_chamada"]  = _agora()
            _agente_stats["ultimo_endpoint"] = request.path
        return f(*args, **kwargs)
    return decorated


def _erro(e: Exception):
    with _agente_lock:
        _agente_stats["erros"] += 1
    return jsonify({"ok": False, "error": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/status")
@_requer_token
def ep_status():
    try:
        uptime = int(time.time() - _inicio_ts) if _inicio_ts else 0
        nft    = _status_nft()
        mon    = _stats_mon()
        sync   = _stats_sync()
        ban    = _stats_autoban()

        ifaces = _detectar_interfaces()

        return jsonify({
            "ok":           True,
            "versao":       VERSAO_AGENTE,
            "sensor":       _cfg_ref.get("sensor_nome", "—"),
            "uptime_seg":   uptime,
            "porta":        _agente_stats["porta"],
            "interfaces":   ifaces,
            "nftables_ok":  nft.get("instalado", False),
            "regras_ativas": sync.get("regras_ativas", 0),
            "monitoramento": {
                "vistos":   mon.get("vistos", 0),
                "enviados": mon.get("enviados", 0),
                "erros":    mon.get("erros", 0),
            },
            "sincronizador": {
                "aplicacoes":   sync.get("aplicacoes", 0),
                "regras_ativas": sync.get("regras_ativas", 0),
                "ultimo_apply": sync.get("ultimo_apply", "—"),
            },
            "autoban": {
                "total_bans": ban.get("total_bans", 0),
                "ips_ativos": ban.get("ips_ativos", 0),
                "ultimo_ip":  ban.get("ultimo_ip",  "—"),
            },
        })
    except Exception as e:
        return _erro(e)


@app.route("/regras")
@_requer_token
def ep_regras():
    try:
        regras = _listar_chain("ms_rules")
        return jsonify({"ok": True, "chain": "ms_rules", "regras": regras})
    except Exception as e:
        return _erro(e)


@app.route("/emergency")
@_requer_token
def ep_emergency():
    try:
        regras = _listar_chain("ms_emergency")
        return jsonify({"ok": True, "chain": "ms_emergency", "regras": regras})
    except Exception as e:
        return _erro(e)


@app.route("/aplicar", methods=["POST"])
@_requer_token
def ep_aplicar():
    try:
        dados     = request.get_json(force=True) or {}
        rules     = dados.get("rules", [])
        iface_map = dados.get("iface_map", {})

        script = gerar_script_nft(rules, iface_map)
        with open(TMP_APPLY, "w", encoding="utf-8") as f:
            f.write(script)

        result = subprocess.run(
            ["nft", "-f", TMP_APPLY],
            capture_output=True, text=True, timeout=15,
        )

        if os.path.exists(TMP_APPLY):
            os.remove(TMP_APPLY)

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "erro desconhecido").strip()
            return jsonify({"ok": False, "error": f"nft: {err}"}), 500

        n = len([r for r in rules if r.get("enabled", True)])
        return jsonify({
            "ok":       True,
            "aplicadas": n,
            "msg":      f"{n} regras aplicadas",
            "versao":   _agora(),
        })
    except Exception as e:
        return _erro(e)


@app.route("/bloquear", methods=["POST"])
@_requer_token
def ep_bloquear():
    try:
        dados   = request.get_json(force=True) or {}
        ip      = dados.get("ip", "").strip()
        iface   = dados.get("iface", "").strip()
        porta   = dados.get("porta", "").strip()
        proto   = (dados.get("proto") or "").strip().lower()
        expires = dados.get("expires", "").strip()
        motivo  = dados.get("motivo", "bloqueio manual").strip()

        if not ip:
            return jsonify({"ok": False, "error": "IP obrigatório"}), 400

        # Monta expressão nft — ordem correta: iface → saddr → proto → dport
        partes = []
        if iface:
            partes.append(f'iifname "{iface}"')
        partes.append(f"ip saddr {ip}")
        if proto and proto not in ("any", ""):
            if proto == "icmp":
                partes.append("ip protocol icmp")
            else:
                partes.append(proto)
        if porta and proto in ("tcp", "udp"):
            partes.append(f"dport {porta}")
        partes.append("drop")

        expr = " ".join(partes)
        cmd  = f'nft add rule inet moonshield ms_emergency {expr} comment "{motivo}"'

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return jsonify({"ok": False, "error": result.stderr.strip()}), 500

        handle = _ultimo_handle("ms_emergency")

        _cancelar_timer(ip)
        seg = _expires_para_segundos(expires)
        if seg and seg > 0:
            t = threading.Timer(seg, _expirar_bloqueio, args=[ip])
            t.daemon = True
            t.start()
            _timers_expiracao[ip] = t

        return jsonify({"ok": True, "handle": handle, "ip": ip})
    except Exception as e:
        return _erro(e)


@app.route("/liberar", methods=["POST"])
@_requer_token
def ep_liberar():
    try:
        dados = request.get_json(force=True) or {}
        ip    = dados.get("ip", "").strip()
        if not ip:
            return jsonify({"ok": False, "error": "IP obrigatório"}), 400

        handles   = _handles_por_ip("ms_emergency", ip)
        removidas = 0
        for h in handles:
            r = subprocess.run(
                ["nft", "delete", "rule", "inet", "moonshield", "ms_emergency", "handle", str(h)],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                removidas += 1

        _cancelar_timer(ip)
        return jsonify({"ok": True, "removidas": removidas})
    except Exception as e:
        return _erro(e)


@app.route("/interfaces")
@_requer_token
def ep_interfaces():
    try:
        return jsonify({"ok": True, "interfaces": _detectar_interfaces()})
    except Exception as e:
        return _erro(e)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_interfaces() -> list[dict]:
    ifaces = []
    try:
        for nome in os.listdir("/sys/class/net/"):
            if nome == "lo":
                continue
            ip = ""
            try:
                r = subprocess.run(
                    ["ip", "-4", "addr", "show", nome],
                    capture_output=True, text=True, timeout=5,
                )
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
                if m:
                    ip = m.group(1)
            except Exception:
                pass

            try:
                state = open(f"/sys/class/net/{nome}/operstate").read().strip()
            except Exception:
                state = "unknown"

            up = (state == "up") or bool(ip)
            ifaces.append({"nome": nome, "ip": ip, "up": up})
    except Exception:
        pass
    return ifaces


def _listar_chain(chain: str) -> list[dict]:
    result = subprocess.run(
        ["nft", "-a", "list", "chain", "inet", "moonshield", chain],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return []

    regras = []
    re_handle = re.compile(r"# handle (\d+)")
    for linha in result.stdout.splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "{" in linha or "}" in linha:
            continue
        if "hook" in linha or "policy" in linha or "jump" in linha or "log" in linha:
            continue
        m = re_handle.search(linha)
        handle = int(m.group(1)) if m else None
        expr   = re_handle.sub("", linha).strip()
        if expr:
            regras.append({
                "handle":  handle,
                "expr":    expr,
                "preview": _expr_para_preview(expr),
            })
    return regras


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


def _ultimo_handle(chain: str) -> int | None:
    result = subprocess.run(
        ["nft", "-a", "list", "chain", "inet", "moonshield", chain],
        capture_output=True, text=True, timeout=10,
    )
    handles = [int(m.group(1)) for m in re.finditer(r"# handle (\d+)", result.stdout)]
    return max(handles) if handles else None


def _handles_por_ip(chain: str, ip: str) -> list[int]:
    result = subprocess.run(
        ["nft", "-a", "list", "chain", "inet", "moonshield", chain],
        capture_output=True, text=True, timeout=10,
    )
    handles = []
    for linha in result.stdout.splitlines():
        if ip in linha:
            m = re.search(r"# handle (\d+)", linha)
            if m:
                handles.append(int(m.group(1)))
    return handles


def _cancelar_timer(ip: str):
    t = _timers_expiracao.pop(ip, None)
    if t:
        t.cancel()


def _expirar_bloqueio(ip: str):
    handles = _handles_por_ip("ms_emergency", ip)
    for h in handles:
        subprocess.run(
            ["nft", "delete", "rule", "inet", "moonshield", "ms_emergency", "handle", str(h)],
            capture_output=True, timeout=10,
        )
    _timers_expiracao.pop(ip, None)


def _expires_para_segundos(expires: str) -> int | None:
    mapa = {"1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}
    return mapa.get(expires)


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def iniciar_agente(cfg: dict, parar: threading.Event) -> threading.Thread:
    global _cfg_ref, _inicio_ts

    _cfg_ref   = cfg
    _inicio_ts = time.time()
    porta      = cfg.get("agente_porta", PORTA_PADRAO)

    with _agente_lock:
        _agente_stats["rodando"]     = True
        _agente_stats["porta"]       = porta
        _agente_stats["iniciado_em"] = _agora()

    def _run():
        # threaded=True — cada request roda em thread própria
        # Resolve travamento quando dashboard TUI ocupa o loop principal
        from werkzeug.serving import make_server
        srv = make_server("0.0.0.0", porta, app, threaded=True)
        srv.timeout = 1
        while not parar.is_set():
            srv.handle_request()
        with _agente_lock:
            _agente_stats["rodando"] = False

    t = threading.Thread(target=_run, name="ms-agente", daemon=True)
    t.start()
    return t


def parar_agente():
    with _agente_lock:
        _agente_stats["rodando"] = False


def obter_stats() -> dict:
    with _agente_lock:
        return dict(_agente_stats)