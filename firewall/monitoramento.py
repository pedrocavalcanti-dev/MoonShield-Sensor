"""
firewall/monitoramento.py
──────────────────────────────────────────────────────────────────────
Loop de monitoramento do firewall.

Lê o journald em tempo real via 'journalctl -f -k -g MS-FWD',
parseia cada linha com analisador.py e envia lotes HTTP para
/firewall/api/ingest/ no MoonShield.

Usa a mesma sessão autenticada (_session, _session_lock) e o mesmo
_stats do nucleo/monitoramento.py — sem duplicar estado.
──────────────────────────────────────────────────────────────────────
"""

import subprocess
import threading
import time

from nucleo.utilitarios import agora
from nucleo.configuracao import salvar_config
from firewall.analisador import parsear_linha

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

BATCH_SIZE    = 20
BATCH_TIMEOUT = 5      # segundos — mesmo padrão do monitoramento IDS
INGEST_PATH   = "/firewall/api/ingest/"

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO LOCAL DO FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

_fw_stats = {
    "vistos":   0,
    "enviados": 0,
    "erros":    0,
    "buffer":   0,
    "ultimo":   "—",
    "rodando":  False,
}
_fw_stats_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def obter_stats() -> dict:
    """Retorna cópia do estado atual. Usado pelo menu para exibir info."""
    with _fw_stats_lock:
        return dict(_fw_stats)


def esta_rodando() -> bool:
    with _fw_stats_lock:
        return _fw_stats["rodando"]


def iniciar_monitoramento(cfg: dict, parar: threading.Event,
                          session, session_lock) -> threading.Thread:
    """
    Inicia o loop do firewall em thread separada.
    Recebe a session e session_lock do nucleo/monitoramento para
    reutilizar a mesma conexão autenticada.
    Retorna a thread iniciada.
    """
    with _fw_stats_lock:
        _fw_stats.update({
            "vistos": 0, "enviados": 0, "erros": 0,
            "buffer": 0, "ultimo": "—", "rodando": True,
        })

    t = threading.Thread(
        target=_loop_firewall,
        args=(cfg, parar, session, session_lock),
        daemon=True,
    )
    t.start()
    return t


def parar_monitoramento():
    """Marca o estado como parado (o evento de parada é controlado externamente)."""
    with _fw_stats_lock:
        _fw_stats["rodando"] = False

# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def _loop_firewall(cfg: dict, parar: threading.Event,
                   session, session_lock):
    """
    Lê journalctl -f em tempo real e envia eventos em lotes.
    Manda heartbeat inicial para registrar o sensor mesmo sem eventos.
    Para quando parar.is_set().
    """
    ingest_url = cfg["Moon_url"].rstrip("/") + INGEST_PATH
    sensor     = cfg["sensor_nome"]
    buffer     = []
    ultimo_env = time.time()

    # ── Heartbeat inicial — registra o sensor no Django imediatamente ────────
    # Garante que o Sensor aparece nas configurações antes do primeiro evento
    _enviar(ingest_url, sensor, [], cfg, session, session_lock)

    cmd = [
        "journalctl", "-f", "-k", "-o", "short",
        "--grep", "MS-FWD",
        "--no-pager",
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        with _fw_stats_lock:
            _fw_stats["rodando"] = False
            _fw_stats["ultimo"]  = "journalctl nao encontrado"
        return

    try:
        while not parar.is_set():
            linha = proc.stdout.readline()

            if not linha:
                if buffer and (time.time() - ultimo_env) >= BATCH_TIMEOUT:
                    ok = _enviar(ingest_url, sensor, buffer, cfg, session, session_lock)
                    with _fw_stats_lock:
                        if ok:
                            _fw_stats["enviados"] += len(buffer)
                            _fw_stats["ultimo"]    = agora()
                        else:
                            _fw_stats["erros"] += len(buffer)
                        _fw_stats["buffer"] = 0
                    buffer.clear()
                    ultimo_env = time.time()
                time.sleep(0.05)
                continue

            evento = parsear_linha(linha.strip())
            if not evento:
                continue

            with _fw_stats_lock:
                _fw_stats["vistos"] += 1

            buffer.append(evento)
            with _fw_stats_lock:
                _fw_stats["buffer"] = len(buffer)

            agora_ts = time.time()
            if len(buffer) >= BATCH_SIZE or (agora_ts - ultimo_env) >= BATCH_TIMEOUT:
                ok = _enviar(ingest_url, sensor, buffer, cfg, session, session_lock)
                with _fw_stats_lock:
                    if ok:
                        _fw_stats["enviados"] += len(buffer)
                        _fw_stats["ultimo"]    = agora()
                    else:
                        _fw_stats["erros"] += len(buffer)
                    _fw_stats["buffer"] = 0
                buffer.clear()
                ultimo_env = agora_ts

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        with _fw_stats_lock:
            _fw_stats["rodando"] = False
# ══════════════════════════════════════════════════════════════════════════════
# ENVIO HTTP
# ══════════════════════════════════════════════════════════════════════════════

def _enviar(url: str, sensor: str, buffer: list,
            cfg: dict, session, session_lock) -> bool:
    """
    Envia lote de eventos para /firewall/api/ingest/.
    Mesmo padrão do _enviar() em nucleo/monitoramento.py.
    """
    try:
        payload = {"sensor": sensor, "eventos": buffer}
        headers = {
            "Content-Type": "application/json",
            "X-MS-TOKEN":   cfg.get("token", ""),
        }
        with session_lock:
            resp = session.post(url, json=payload, timeout=5, headers=headers)

        with _fw_stats_lock:
            _fw_stats["ultimo"] = f"HTTP {resp.status_code}"

        if resp.status_code == 403:
            try:
                dados = resp.json()
                if "token" in dados:
                    cfg["token"] = dados["token"]
                    salvar_config(cfg)
            except Exception:
                pass
            return False

        if not (200 <= resp.status_code < 300):
            return False

        try:
            novo = resp.json().get("token", "")
            if novo and novo != cfg.get("token", ""):
                cfg["token"] = novo
                salvar_config(cfg)
        except Exception:
            pass

        return True

    except Exception as e:
        with _fw_stats_lock:
            _fw_stats["ultimo"] = f"ERR:{str(e)[:28]}"
        return False