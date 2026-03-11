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
    "heartbeats": 0,
    "login_ok":   False,
}
_stats_lock = threading.Lock()

# Sessão HTTP compartilhada — mantém cookies de sessão entre requisições
_session = requests.Session()
_session_lock = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
# AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _autenticar(cfg: dict) -> bool:
    """
    Faz login no MoonShield e armazena os cookies na _session global.
    Retorna True se autenticado com sucesso.

    O sensor precisa de sessão autenticada porque api/data/ usa @login_required.
    O endpoint api/ingest/ aceita X-MS-TOKEN, mas para consistência e segurança
    mantemos a sessão ativa.
    """
    from nucleo.interface import _fazer_login

    usuario = cfg.get("Moon_usuario", "")
    senha   = cfg.get("Moon_senha", "")

    if not usuario or not senha:
        return True

    moonshield_url = cfg["Moon_url"].rstrip("/")
    login_url      = moonshield_url + "/auth/login/"

    try:
        with _session_lock:
            r = _session.get(login_url, timeout=5)
            csrf = _session.cookies.get("csrftoken", "")
            if not csrf:
                import re
                m = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
                csrf = m.group(1) if m else ""

            r2 = _session.post(
                login_url,
                data={
                    "username":            usuario,
                    "password":            senha,
                    "csrfmiddlewaretoken": csrf,
                },
                headers={"Referer": login_url},
                timeout=5,
                allow_redirects=True,
            )

            ok = "/auth/login/" not in r2.url and r2.status_code == 200

        with _stats_lock:
            _stats["login_ok"] = ok

        return ok

    except Exception:
        with _stats_lock:
            _stats["login_ok"] = False
        return False


# ══════════════════════════════════════════════════════════════════════════════
# TELA DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

def tela_sensor(cfg: dict):
    from nucleo.interface import (
        cabecalho, print_resultado, linha_vazia, linha_texto,
        aguardar_enter, limpar, C_DIM,
    )

    if not cfg["Moon_url"]:
        cabecalho(cfg)
        print_resultado(False, "URL do MoonShield não configurada. Configure primeiro.")
        linha_vazia()
        aguardar_enter()
        return

    if not os.path.exists(cfg["eve_path"]):
        cabecalho(cfg)
        print_resultado(False, f"eve.json não encontrado: {cfg['eve_path']}")
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
        _stats["login_ok"]   = False
        _stats["rodando"]    = True

    limpar()
    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        print(f"  Autenticando como {cfg['Moon_usuario']}...", flush=True)
        ok = _autenticar(cfg)
        if ok:
            print("  ✔ Login OK")
        else:
            print("  ✗ Login falhou — verifique as credenciais (opção [8])")
            print("  Continuando sem autenticação...")
        time.sleep(1)

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
        linha_texto, C_TITULO, C_DIM, C_NORMAL, C_OK, C_ERRO, C_AVISO,
    )
    from nucleo.configuracao import VERSION

    while True:
        with _stats_lock:
            if not _stats["rodando"]:
                break
            seen     = _stats["seen"]
            sent     = _stats["sent"]
            erros    = _stats["erros"]
            buf      = _stats["buffer"]
            ultimo   = _stats["ultimo"]
            hb       = _stats["heartbeats"]
            login_ok = _stats["login_ok"]

        usuario = cfg.get("Moon_usuario", "")
        login_str = f"✔ {usuario}" if login_ok else ("✗ não autenticado" if usuario else "— sem credenciais")
        login_cor = C_OK if login_ok else (C_ERRO if usuario else C_DIM)

        limpar()
        topo()
        linha_texto("MOONSHIELD — SENSOR  ATIVO", C_TITULO, "centro")
        separador()
        linha_texto(f"MoonShield : {cfg['Moon_url']}", C_DIM)
        linha_texto(f"Sensor     : {cfg['sensor_nome']}", C_DIM)
        linha_texto(f"Login      : {login_str}", login_cor)
        linha_texto(f"Eve.json   : {cfg['eve_path']}", C_DIM)
        separador()
        linha_texto(f"  Eventos vistos    : {seen:,}", C_NORMAL)
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

HEARTBEAT_INTERVAL    = 30    # segundos entre heartbeats
DEFAULT_BATCH_TIMEOUT = 2     # segundos sem linha nova para enviar buffer pendente
REAUTH_INTERVAL       = 3600  # 1 hora — renova sessão periodicamente


def _loop_sensor(cfg: dict):
    eve_path      = cfg["eve_path"]
    ingest_url    = cfg["Moon_url"] + "/incidentes/api/ingest/"
    sensor_nome   = cfg["sensor_nome"]
    batch_size    = int(cfg.get("batch_size", 20))
    batch_timeout = int(cfg.get("batch_timeout", DEFAULT_BATCH_TIMEOUT))
    min_sev       = int(cfg.get("min_severity", 4))

    buffer      = []
    last_send   = time.time()
    last_reauth = time.time()

    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)

        while True:
            with _stats_lock:
                if not _stats["rodando"]:
                    break

            # Reautenticação periódica (mantém sessão viva)
            if time.time() - last_reauth >= REAUTH_INTERVAL:
                _autenticar(cfg)
                last_reauth = time.time()

            line = f.readline()

            # ── Sem linha nova ────────────────────────────────────────────────
            if not line:
                agora_ts = time.time()
                tempo_desde_envio = agora_ts - last_send

                if buffer and tempo_desde_envio >= batch_timeout:
                    ok = _enviar(ingest_url, sensor_nome, buffer, cfg)
                    with _stats_lock:
                        if ok:
                            _stats["sent"]  += len(buffer)
                            _stats["ultimo"] = agora()
                        else:
                            _stats["erros"] += len(buffer)
                        _stats["buffer"] = 0
                    buffer.clear()
                    last_send = agora_ts

                elif not buffer and tempo_desde_envio >= HEARTBEAT_INTERVAL:
                    ok = _enviar(ingest_url, sensor_nome, [], cfg)
                    with _stats_lock:
                        if ok:
                            _stats["heartbeats"] += 1
                            _stats["ultimo"]      = agora()
                        else:
                            _stats["erros"] += 1
                    last_send = agora_ts

                time.sleep(0.1)
                continue

            # ── Processa linha ────────────────────────────────────────────────
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

            if len(buffer) >= batch_size or (time.time() - last_send) >= batch_timeout:
                ok = _enviar(ingest_url, sensor_nome, buffer, cfg)
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
    """
    Envia eventos para o MoonShield.
    Usa a _session global (que mantém cookies de autenticação).
    Se receber 401/403, tenta reautenticar uma vez.
    """
    try:
        payload = {"sensor": sensor_nome, "eventos": buffer}
        headers = {
            "Content-Type": "application/json",
            "X-MS-TOKEN":   cfg.get("token", ""),
        }

        with _session_lock:
            resp = _session.post(url, json=payload, timeout=5, headers=headers)

        # Sessão expirou — reautentica e tenta de novo
        if resp.status_code in (401, 403):
            _autenticar(cfg)
            with _session_lock:
                resp = _session.post(url, json=payload, timeout=5, headers=headers)

        if 200 <= resp.status_code < 300:
            data = resp.json()
            if data.get("token"):
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

    print(f"[{agora()}] MoonShield Sensor v{VERSION} iniciando em modo automático...")
    print(f"[{agora()}] MoonShield : {cfg['Moon_url']}")
    print(f"[{agora()}] Sensor     : {cfg['sensor_nome']}")
    print(f"[{agora()}] Eve        : {cfg['eve_path']}")
    print(f"[{agora()}] Heartbeat a cada {HEARTBEAT_INTERVAL}s")

    if not cfg["Moon_url"]:
        print(f"[{agora()}] ERRO: URL do MoonShield não configurada.")
        sys.exit(1)

    if not os.path.exists(cfg["eve_path"]):
        print(f"[{agora()}] ERRO: eve.json não encontrado: {cfg['eve_path']}")
        sys.exit(1)

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        print(f"[{agora()}] Autenticando como {cfg['Moon_usuario']}...")
        ok = _autenticar(cfg)
        print(f"[{agora()}] Login {'OK' if ok else 'FALHOU — continuando sem autenticação'}")
    else:
        print(f"[{agora()}] Sem credenciais configuradas — modo sem autenticação")

    with _stats_lock:
        _stats["rodando"] = True

    def heartbeat_log():
        while True:
            time.sleep(60)
            with _stats_lock:
                s  = _stats["seen"]
                e  = _stats["sent"]
                er = _stats["erros"]
                hb = _stats["heartbeats"]
                lo = _stats["login_ok"]
            print(
                f"[{agora()}] stats | vistos={s} | enviados={e} | "
                f"erros={er} | heartbeats={hb} | login={'ok' if lo else 'falhou'}",
                flush=True,
            )

    threading.Thread(target=heartbeat_log, daemon=True).start()

    try:
        _loop_sensor(cfg)
    except KeyboardInterrupt:
        print(f"\n[{agora()}] MoonShield Sensor encerrado.")
        sys.exit(0)