"""
firewall/monitoramento/monitoramento.py
──────────────────────────────────────────────────────────────────────
Loop de monitoramento do firewall.

Lê o journald em tempo real via 'journalctl -f -k -g MS-',
parseia cada linha com analisador.py e envia lotes HTTP para
/firewall/api/ingest/ no MoonShield.

v2: corrige import typo (nucelo→nucleo), contadores drops/allows,
    heartbeat periódico a cada 5 min, VERSAO_MONITORAMENTO.
──────────────────────────────────────────────────────────────────────
"""

import os
import subprocess
import threading
import time

from nucleo.utilitarios import agora
from nucleo.configuracao import salvar_config
from firewall.nucleo.analisador import parsear_linha   # fix: nucelo → nucleo

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_MONITORAMENTO = "2.0"
BATCH_SIZE           = 20
BATCH_TIMEOUT        = 5      # segundos
HEARTBEAT_INTERVAL   = 300    # 5 minutos — mantém last_seen atualizado no Django
INGEST_PATH          = "/firewall/api/ingest/"

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO LOCAL DO FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

_fw_stats = {
    "vistos":         0,
    "enviados":       0,
    "erros":          0,
    "buffer":         0,
    "ultimo":         "—",
    "rodando":        False,
    "drops_sessao":   0,
    "allows_sessao":  0,
    "ultimo_src_ip":  "—",
}
_fw_stats_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def obter_stats() -> dict:
    with _fw_stats_lock:
        return dict(_fw_stats)


def esta_rodando() -> bool:
    with _fw_stats_lock:
        return _fw_stats["rodando"]


def iniciar_monitoramento(cfg: dict, parar: threading.Event,
                          session, session_lock) -> threading.Thread:
    with _fw_stats_lock:
        _fw_stats.update({
            "vistos": 0, "enviados": 0, "erros": 0, "buffer": 0,
            "ultimo": "—", "rodando": True,
            "drops_sessao": 0, "allows_sessao": 0, "ultimo_src_ip": "—",
        })

    t = threading.Thread(
        target=_loop_firewall,
        args=(cfg, parar, session, session_lock),
        daemon=True,
    )
    t.start()
    return t


def parar_monitoramento():
    with _fw_stats_lock:
        _fw_stats["rodando"] = False

# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE INTERFACES
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_interfaces(cfg: dict) -> list:
    """
    Detecta interfaces de rede reais do Linux via /sys/class/net/.
    Considera UP: operstate == 'up' OU interface tem IP atribuído
    (interfaces em modo PROMISC reportam operstate 'unknown' mesmo ativas).
    Também atualiza iface_map usando interface_wan/interface_lan do wizard.
    """
    interfaces = []
    try:
        for nome in sorted(os.listdir('/sys/class/net/')):
            if nome == 'lo':
                continue
            try:
                result = subprocess.run(
                    ['ip', '-4', 'addr', 'show', nome],
                    capture_output=True, text=True, timeout=3,
                )
                ip = ''
                for line in result.stdout.splitlines():
                    if 'inet ' in line:
                        ip = line.strip().split()[1].split('/')[0]
                        break

                with open(f'/sys/class/net/{nome}/operstate') as f:
                    state = f.read().strip()

                up = (state == 'up') or bool(ip)
                interfaces.append({'nome': nome, 'ip': ip, 'up': up})
            except Exception:
                pass
    except Exception:
        pass

    wan = cfg.get('interface_wan', '')
    lan = cfg.get('interface_lan', '')
    if wan or lan:
        iface_map = dict(cfg.get('iface_map', {}))
        if wan:
            iface_map['WAN'] = wan
        if lan:
            iface_map['LAN'] = lan
        cfg['iface_map'] = iface_map
        salvar_config(cfg)

    return interfaces

# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def _loop_firewall(cfg: dict, parar: threading.Event,
                   session, session_lock):
    ingest_url = cfg["Moon_url"].rstrip("/") + INGEST_PATH
    sensor     = cfg["sensor_nome"]
    buffer     = []
    ultimo_env = time.time()

    # Heartbeat inicial — detecta interfaces e registra o sensor
    cfg['interfaces'] = _detectar_interfaces(cfg)
    _enviar(ingest_url, sensor, [], cfg, session, session_lock)
    ultimo_heartbeat = time.time()

    cmd = [
        "journalctl", "-f", "-k", "-o", "short",
        "--grep", "MS-",
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

            # Heartbeat periódico — mantém last_seen atualizado no Django
            if time.time() - ultimo_heartbeat >= HEARTBEAT_INTERVAL:
                _enviar(ingest_url, sensor, [], cfg, session, session_lock)
                ultimo_heartbeat = time.time()

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
                # v2: contadores por ação
                acao = evento.get("acao", "").upper()
                if acao in ("DROP", "DENY", "REJECT"):
                    _fw_stats["drops_sessao"] += 1
                elif acao in ("LOG", "ALLOW", "ACCEPT"):
                    _fw_stats["allows_sessao"] += 1
                _fw_stats["ultimo_src_ip"] = evento.get("src_ip", "—")

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
    try:
        payload = {"sensor": sensor, "eventos": buffer}
        if not buffer:
            payload["interfaces"] = cfg.get("interfaces", [])

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