import os
import time
import json
import threading
import requests

from nucleo.configuracao import TIPOS_ACEITOS, salvar_config
from nucleo.utilitarios import agora

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO GLOBAL DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

_stats = {
    "seen":       0,
    "sent":       0,
    "erros":      0,
    "buffer":     0,
    "ultimo":     "—",
    "rodando":    False,
    "heartbeats": 0,   # novo: conta heartbeats enviados
}
_stats_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# TELA DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

def tela_sensor(cfg: dict):
    from nucleo.interface import (
        cabecalho, print_resultado, linha_vazia,
        aguardar_enter, limpar,
    )

    if not cfg["jarvis_url"]:
        cabecalho(cfg)
        print_resultado(False, "URL do Jarvis não configurada. Configure primeiro.")
        linha_vazia()
        aguardar_enter()
        return

    if not os.path.exists(cfg["eve_path"]):
        cabecalho(cfg)
        print_resultado(False, f"eve.json não encontrado: {cfg['eve_path']}")
        from nucleo.interface import linha_texto, C_DIM
        linha_texto("Verifique se o Suricata está instalado e rodando.", C_DIM)
        linha_texto("Use a opção [5] para configurar o caminho correto.", C_DIM)
        linha_vazia()
        aguardar_enter()
        return

    # Reset stats
    with _stats_lock:
        _stats["seen"]       = 0
        _stats["sent"]       = 0
        _stats["erros"]      = 0
        _stats["buffer"]     = 0
        _stats["ultimo"]     = "—"
        _stats["heartbeats"] = 0
        _stats["rodando"]    = True

    t_display = threading.Thread(target=_loop_display, args=(cfg,), daemon=True)
    t_display.start()

    try:
        _loop_sensor(cfg)
    except KeyboardInterrupt:
        pass
    finally:
        with _stats_lock:
            _stats["rodando"] = False
        time.sleep(0.3)
        limpar()


# ══════════════════════════════════════════════════════════════════════════════
# LOOP DE DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

def _loop_display(cfg: dict):
    from nucleo.interface import (
        limpar, topo, separador, fundo,
        linha_texto, C_TITULO, C_DIM, C_NORMAL, C_OK, C_ERRO,
    )
    from nucleo.configuracao import VERSION

    while True:
        with _stats_lock:
            if not _stats["rodando"]:
                break
            seen   = _stats["seen"]
            sent   = _stats["sent"]
            erros  = _stats["erros"]
            buf    = _stats["buffer"]
            ultimo = _stats["ultimo"]
            hb     = _stats["heartbeats"]

        limpar()
        topo()
        linha_texto("JARVIS GUARD — SENSOR  ATIVO", C_TITULO, "centro")
        separador()
        linha_texto(f"Jarvis  : {cfg['jarvis_url']}", C_DIM)
        linha_texto(f"Sensor  : {cfg['sensor_nome']}", C_DIM)
        linha_texto(f"Eve.json: {cfg['eve_path']}", C_DIM)
        separador()
        linha_texto(f"  Eventos vistos   : {seen:,}", C_NORMAL)
        linha_texto(f"  Eventos enviados  : {sent:,}", C_OK)
        linha_texto(f"  Erros de envio    : {erros:,}", C_ERRO if erros > 0 else C_DIM)
        linha_texto(f"  Buffer pendente   : {buf}", C_DIM)
        linha_texto(f"  Heartbeats        : {hb}", C_DIM)
        linha_texto(f"  Último envio      : {ultimo}", C_DIM)
        separador()
        linha_texto("  Pressione Ctrl+C para parar o sensor", C_DIM)
        fundo()

        time.sleep(2)


# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

# Intervalo máximo entre envios (mesmo sem eventos).
# O Django considera o sensor offline após ONLINE_THRESHOLD_SEGUNDOS (models.py).
# Mantenha HEARTBEAT_INTERVAL bem abaixo desse threshold.
HEARTBEAT_INTERVAL = 30   # segundos — envia POST a cada 30s mesmo sem eventos


def _loop_sensor(cfg: dict):
    eve_path      = cfg["eve_path"]
    jarvis_url    = cfg["jarvis_url"] + "/incidentes/api/ingest/"
    sensor_nome   = cfg["sensor_nome"]
    batch_size    = int(cfg.get("batch_size", 20))
    batch_timeout = int(cfg.get("batch_timeout", 5))
    min_sev       = int(cfg.get("min_severity", 4))

    buffer    = []
    last_send = time.time()

    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            with _stats_lock:
                if not _stats["rodando"]:
                    break

            line = f.readline()

            # ── Sem linha nova no arquivo ────────────────────────────────────
            if not line:
                agora_ts = time.time()
                tempo_desde_envio = agora_ts - last_send

                # Envia se: buffer cheio E timeout atingido
                if buffer and tempo_desde_envio >= batch_timeout:
                    ok = _enviar(jarvis_url, sensor_nome, buffer, cfg)
                    with _stats_lock:
                        if ok:
                            _stats["sent"]  += len(buffer)
                            _stats["ultimo"] = agora()
                        else:
                            _stats["erros"] += len(buffer)
                        _stats["buffer"] = 0
                    buffer.clear()
                    last_send = agora_ts

                # ── HEARTBEAT: envia POST vazio se ficou muito tempo sem enviar
                elif not buffer and tempo_desde_envio >= HEARTBEAT_INTERVAL:
                    ok = _enviar(jarvis_url, sensor_nome, [], cfg)
                    with _stats_lock:
                        if ok:
                            _stats["heartbeats"] += 1
                            _stats["ultimo"]      = agora()
                        else:
                            _stats["erros"] += 1
                    last_send = agora_ts

                time.sleep(0.2)
                continue

            # ── Processamento normal da linha ────────────────────────────────
            line = line.strip()
            if not line:
                continue

            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            with _stats_lock:
                _stats["seen"] += 1

            tipo = evt.get("event_type", "").lower()
            if tipo not in TIPOS_ACEITOS:
                continue

            if tipo == "alert":
                sev_num = evt.get("alert", {}).get("severity", 4)
                if sev_num > min_sev:
                    continue

            buffer.append(evt)

            with _stats_lock:
                _stats["buffer"] = len(buffer)

            batch_cheio   = len(buffer) >= batch_size
            tempo_expirou = (time.time() - last_send) >= batch_timeout

            if batch_cheio or tempo_expirou:
                ok = _enviar(jarvis_url, sensor_nome, buffer, cfg)
                with _stats_lock:
                    if ok:
                        _stats["sent"]  += len(buffer)
                        _stats["ultimo"] = agora()
                    else:
                        _stats["erros"] += len(buffer)
                    _stats["buffer"] = 0
                buffer.clear()
                last_send = time.time()


# ══════════════════════════════════════════════════════════════════════════════
# ENVIO HTTP
# ══════════════════════════════════════════════════════════════════════════════

def _enviar(url: str, sensor_nome: str, buffer: list, cfg: dict) -> bool:
    try:
        payload = {"sensor": sensor_nome, "eventos": buffer}
        resp = requests.post(
            url,
            json=payload,
            timeout=5,
            headers={
                "Content-Type": "application/json",
                "X-JG-TOKEN":   cfg.get("token", ""),
            },
        )
        if 200 <= resp.status_code < 300:
            data = resp.json()
            # Salva o token na primeira vez que o servidor retorna
            if data.get("token") and not cfg.get("token"):
                cfg["token"] = data["token"]
                salvar_config(cfg)
            return True
        return False
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# MODO --auto (systemd / headless)
# ══════════════════════════════════════════════════════════════════════════════

def modo_auto(cfg: dict):
    import sys
    from nucleo.configuracao import VERSION

    print(f"[{agora()}] JG-Sensor v{VERSION} iniciando em modo automático...")
    print(f"[{agora()}] Jarvis : {cfg['jarvis_url']}")
    print(f"[{agora()}] Sensor : {cfg['sensor_nome']}")
    print(f"[{agora()}] Eve    : {cfg['eve_path']}")
    print(f"[{agora()}] Heartbeat a cada {HEARTBEAT_INTERVAL}s")

    if not cfg["jarvis_url"]:
        print(f"[{agora()}] ERRO: URL do Jarvis não configurada. Execute sem --auto primeiro.")
        sys.exit(1)

    if not os.path.exists(cfg["eve_path"]):
        print(f"[{agora()}] ERRO: eve.json não encontrado: {cfg['eve_path']}")
        sys.exit(1)

    with _stats_lock:
        _stats["rodando"] = True

    def heartbeat_log():
        """Apenas loga stats periodicamente no stdout (systemd/journald)."""
        while True:
            time.sleep(60)
            with _stats_lock:
                s  = _stats["seen"]
                e  = _stats["sent"]
                er = _stats["erros"]
                hb = _stats["heartbeats"]
            print(
                f"[{agora()}] stats | vistos={s} | enviados={e} | "
                f"erros={er} | heartbeats={hb}",
                flush=True,
            )

    threading.Thread(target=heartbeat_log, daemon=True).start()

    try:
        _loop_sensor(cfg)
    except KeyboardInterrupt:
        print(f"\n[{agora()}] Sensor encerrado.")
        sys.exit(0)