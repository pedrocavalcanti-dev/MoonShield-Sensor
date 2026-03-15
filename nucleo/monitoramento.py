import os
import sys
import time
import json
import threading
import requests

from nucleo.configuracao import TIPOS_ACEITOS, salvar_config
from nucleo.utilitarios import agora

# ══════════════════════════════════════════════════════════════════════════════
# RADAR — importado de nucleo/radar.py
# ══════════════════════════════════════════════════════════════════════════════

try:
    from nucleo import radar as _radar
    _RADAR_OK = True
except ImportError:
    _radar = None
    _RADAR_OK = False

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO GLOBAL
# ══════════════════════════════════════════════════════════════════════════════

_stats = {
    "seen": 0, "sent": 0, "erros": 0, "buffer": 0,
    "ultimo": "—", "rodando": False, "heartbeats": 0,
    "login_ok": False, "ultimo_status": "—",
}
_stats_lock   = threading.Lock()
_session      = requests.Session()
_session_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _autenticar(cfg: dict) -> bool:
    usuario = cfg.get("Moon_usuario", "")
    senha   = cfg.get("Moon_senha", "")
    if not usuario or not senha:
        return True
    moonshield_url = cfg["Moon_url"].rstrip("/")
    login_url      = moonshield_url + "/auth/login/"
    try:
        with _session_lock:
            r    = _session.get(login_url, timeout=5)
            csrf = _session.cookies.get("csrftoken", "")
            if not csrf:
                import re
                m    = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
                csrf = m.group(1) if m else ""
            r2 = _session.post(
                login_url,
                data={"username": usuario, "password": senha,
                      "csrfmiddlewaretoken": csrf},
                headers={"Referer": login_url},
                timeout=5, allow_redirects=True,
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
# CURSOR
# ══════════════════════════════════════════════════════════════════════════════

def _cursor_path(eve_path): return eve_path + ".moonshield.cursor"

def _ler_cursor(eve_path):
    try:
        with open(_cursor_path(eve_path)) as f: return int(f.read().strip())
    except Exception: return None

def _salvar_cursor(eve_path, pos):
    try:
        with open(_cursor_path(eve_path), "w") as f: f.write(str(pos))
    except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# ANSI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _hide():    return "\033[?25l"
def _show():    return "\033[?25h"
def _alt_in():  return "\033[?1049h"
def _alt_out(): return "\033[?1049l"
def _home():    return "\033[H"

def _enable_ansi_windows():
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# TELA DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

def _key_reader(stop_event):
    """
    Thread que lê stdin em modo raw.
    Ctrl+C (\x03), Ctrl+X (\x18) ou 'q' param o sensor e voltam ao menu.
    """
    import select, termios, tty
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except Exception:
        return
    def _r():
        try:
            tty.setraw(fd)
            while not stop_event.is_set():
                r,_,_ = select.select([sys.stdin],[],[],0.1)
                if r:
                    ch = sys.stdin.read(1)
                    if ch in ('\x03','\x18','\x04','q','Q'):
                        stop_event.set()
                        break
        except Exception:
            stop_event.set()
        finally:
            try: termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception: pass
    threading.Thread(target=_r, daemon=True).start()


def tela_sensor(cfg: dict):
    from nucleo.interface import (
        cabecalho, print_resultado, linha_vazia,
        linha_texto, aguardar_enter, C_DIM,
    )

    if not cfg["Moon_url"]:
        cabecalho(cfg)
        print_resultado(False, "URL do MoonShield não configurada. Configure primeiro.")
        linha_vazia(); aguardar_enter(); return

    if not os.path.exists(cfg["eve_path"]):
        cabecalho(cfg)
        print_resultado(False, f"eve.json não encontrado: {cfg['eve_path']}")
        linha_texto("Verifique se o Suricata está instalado e rodando.", C_DIM)
        linha_texto("Use a opção [5] para configurar o caminho correto.", C_DIM)
        linha_vazia(); aguardar_enter(); return

    with _stats_lock:
        _stats.update({"seen":0,"sent":0,"erros":0,"buffer":0,
                        "ultimo":"—","heartbeats":0,"login_ok":False,
                        "rodando":True,"ultimo_status":"—"})

    _enable_ansi_windows()

    import sys
    sys.stdout.write(_alt_in())
    sys.stdout.write(_hide())
    sys.stdout.flush()

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.write(f"  Autenticando como {cfg['Moon_usuario']}...\n")
        sys.stdout.flush()
        ok = _autenticar(cfg)
        sys.stdout.write("  ✔ Login OK\n" if ok else "  ✗ Login falhou — continuando sem autenticação\n")
        sys.stdout.flush()
        time.sleep(1)

    # Evento de parada — qualquer thread pode setar, o sensor encerra
    _stop = threading.Event()
    _key_reader(_stop)

    t_display = threading.Thread(target=_loop_display, args=(cfg, _stop), daemon=True)
    t_display.start()

    try:
        _loop_sensor(cfg, _stop)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()
        with _stats_lock: _stats["rodando"] = False
        time.sleep(0.2)
        sys.stdout.write(_show())
        sys.stdout.write(_alt_out())
        sys.stdout.flush()

# ══════════════════════════════════════════════════════════════════════════════
# LOOP DE DISPLAY — stats à esquerda, radar à direita
# ══════════════════════════════════════════════════════════════════════════════

_SPIN  = ['◐', '◓', '◑', '◒']
_LW    = 36    # largura do painel de stats

# Número de linhas que o radar ocupa (H + 4 da assinatura).
# Se radar não disponível, usamos esse valor como fallback.
_TOTAL = (_radar.TOTAL_LINES if _RADAR_OK else 31)


def _loop_display(cfg: dict, _stop: threading.Event = None):
    import sys

    _R   = '\033[0m'
    C_T  = '\033[38;5;75m'   # título
    C_D  = '\033[38;5;238m'  # dim
    C_N  = '\033[38;5;252m'  # normal
    C_OK = '\033[38;5;84m'
    C_ER = '\033[38;5;196m'
    C_AV = '\033[38;5;214m'
    C_NE = '\033[38;5;87m'

    W   = _LW
    idx = 0

    while True:
        with _stats_lock:
            if not _stats["rodando"]: break
            seen=_stats["seen"]; sent=_stats["sent"]; erros=_stats["erros"]
            buf=_stats["buffer"]; ultimo=_stats["ultimo"]
            hb=_stats["heartbeats"]; lo=_stats["login_ok"]; us=_stats["ultimo_status"]

        usuario   = cfg.get("Moon_usuario","")
        login_str = (f"✔ {usuario}" if lo else ("✗ nao autenticado" if usuario else "— sem credenciais"))
        login_cor = C_OK if lo else (C_ER if usuario else C_D)

        if buf > 0:      spin_txt=f"[ ▶ ]  enviando {buf} eventos..."; spin_cor=C_AV
        elif erros > 0 and us not in ("HTTP 200","—"):
                         spin_txt=f"[ ✗ ]  erro: {us}";               spin_cor=C_ER
        else:            spin_txt=f"[{_SPIN[idx%4]}]  radar ativo";   spin_cor=C_NE

        # ── helpers ──────────────────────────────────────────────────────────
        def row(t, c=C_D): return (t, c)
        def box(s, c=C_D): return row(f"║  {s[:W-4]:<{W-4}}║", c)
        def sep(l='╠',r='╣'): return row(l+'═'*(W-2)+r, C_D)
        def blank(): return row('║'+' '*(W-2)+'║', C_D)

        # ── painel esquerdo — exatamente _TOTAL linhas ────────────────────────
        left = [
            row('╔'+'═'*(W-2)+'╗',                C_D),   # 1
            box('MOONSHIELD — SENSOR ATIVO',        C_T),   # 2
            sep(),                                           # 3
            box(f"URL    : {cfg['Moon_url']}",      C_D),   # 4
            box(f"Sensor : {cfg['sensor_nome']}",   C_D),   # 5
            box(f"Login  : {login_str}",            login_cor), # 6
            box(f"Eve    : {cfg['eve_path']}",      C_D),   # 7
            sep(),                                           # 8
            box(spin_txt,                           spin_cor), # 9
            sep(),                                           # 10
            box(f"Vistos    : {seen:,}",            C_N),   # 11
            box(f"Enviados  : {sent:,}",            C_OK),  # 12
            box(f"Erros     : {erros:,}", C_ER if erros else C_D), # 13
            box(f"Buffer    : {buf}",               C_D),   # 14
            box(f"Heartbeat : {hb}",                C_D),   # 15
            box(f"Último    : {ultimo}",            C_D),   # 16
            box(f"HTTP      : {us}",                C_D),   # 17
            sep(),                                           # 18
            box('Ctrl+C para parar',                C_D),   # 19
            row('╚'+'═'*(W-2)+'╝',                C_D),   # 20
        ]
        while len(left) < _TOTAL: left.append(blank())
        left = left[:_TOTAL]

        # ── coluna direita: radar ─────────────────────────────────────────────
        if _RADAR_OK:
            right = _radar.get_radar_lines() + _radar.get_signature_lines()
        else:
            right = ['  (nucleo/radar.py nao encontrado)'] + ['']*(_TOTAL-1)

        while len(right) < _TOTAL: right.append('')
        right = right[:_TOTAL]

        # ── monta frame ───────────────────────────────────────────────────────
        frame = [_home()]
        for (lt, lc), rl in zip(left, right):
            frame.append('\033[2K' + lc + lt + _R + '   ' + rl)

        sys.stdout.write('\n'.join(frame))
        sys.stdout.flush()

        idx += 1
        time.sleep(0.05)

# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

HEARTBEAT_INTERVAL    = 15
DEFAULT_BATCH_TIMEOUT = 2
REAUTH_INTERVAL       = 3600


def _loop_sensor(cfg: dict, _stop: threading.Event = None):
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
        cursor_salvo = _ler_cursor(eve_path)
        f.seek(cursor_salvo if cursor_salvo is not None else 0)

        while True:
            with _stats_lock:
                if not _stats["rodando"]: break
            if _stop and _stop.is_set(): break
            if _stop and _stop.is_set(): break

            if time.time() - last_reauth >= REAUTH_INTERVAL:
                _autenticar(cfg); last_reauth = time.time()

            line = f.readline()

            if not line:
                agora_ts = time.time()
                dt       = agora_ts - last_send

                if buffer and dt >= batch_timeout:
                    ok = _enviar(ingest_url, sensor_nome, buffer, cfg)
                    pos = f.tell()
                    with _stats_lock:
                        if ok: _stats["sent"]+=len(buffer); _stats["ultimo"]=agora(); _salvar_cursor(eve_path,pos)
                        else:  _stats["erros"]+=len(buffer)
                        _stats["buffer"]=0
                    buffer.clear(); last_send = agora_ts

                elif not buffer and dt >= HEARTBEAT_INTERVAL:
                    ok = _enviar(ingest_url, sensor_nome, [], cfg)
                    with _stats_lock:
                        if ok: _stats["heartbeats"]+=1; _stats["ultimo"]=agora()
                        else:  _stats["erros"]+=1
                    last_send = agora_ts

                time.sleep(0.1)
                continue

            line = line.strip()
            if not line: continue

            try: evt = json.loads(line)
            except json.JSONDecodeError: continue

            with _stats_lock: _stats["seen"] += 1

            tipo = evt.get("event_type","").lower()
            if tipo not in TIPOS_ACEITOS: continue

            if tipo == "alert":
                sev = evt.get("alert",{}).get("severity",4)
                if sev > min_sev: continue
                # Alerta real → ping visual no radar
                if _RADAR_OK: _radar.add_ping()

            buffer.append(evt)
            with _stats_lock: _stats["buffer"] = len(buffer)

            if len(buffer) >= batch_size or (time.time()-last_send) >= batch_timeout:
                ok = _enviar(ingest_url, sensor_nome, buffer, cfg)
                pos = f.tell()
                with _stats_lock:
                    if ok: _stats["sent"]+=len(buffer); _stats["ultimo"]=agora(); _salvar_cursor(eve_path,pos)
                    else:  _stats["erros"]+=len(buffer)
                    _stats["buffer"]=0
                buffer.clear(); last_send = time.time()

# ══════════════════════════════════════════════════════════════════════════════
# ENVIO HTTP
# ══════════════════════════════════════════════════════════════════════════════

def _enviar(url, sensor_nome, buffer, cfg) -> bool:
    try:
        payload = {"sensor": sensor_nome, "eventos": buffer}
        headers = {"Content-Type": "application/json", "X-MS-TOKEN": cfg.get("token","")}
        with _session_lock:
            resp = _session.post(url, json=payload, timeout=5, headers=headers)

        with _stats_lock: _stats["ultimo_status"] = f"HTTP {resp.status_code}"

        if resp.status_code == 403:
            try:
                dados = resp.json()
                if "token" in dados: cfg["token"]=dados["token"]; salvar_config(cfg)
            except Exception: pass
            return False

        if not (200 <= resp.status_code < 300): return False

        try:
            novo = resp.json().get("token","")
            if novo and novo != cfg.get("token",""): cfg["token"]=novo; salvar_config(cfg)
        except Exception: pass
        return True

    except requests.exceptions.ConnectionError:
        with _stats_lock: _stats["ultimo_status"]="CONN ERR"
        return False
    except Exception as e:
        with _stats_lock: _stats["ultimo_status"]=f"ERR:{str(e)[:28]}"
        return False

# ══════════════════════════════════════════════════════════════════════════════
# MODO --auto
# ══════════════════════════════════════════════════════════════════════════════

def modo_auto(cfg: dict):
    import sys
    from nucleo.configuracao import VERSION

    print(f"[{agora()}] MoonShield Sensor v{VERSION} iniciando em modo automatico...")
    print(f"[{agora()}] MoonShield : {cfg['Moon_url']}")
    print(f"[{agora()}] Sensor     : {cfg['sensor_nome']}")
    print(f"[{agora()}] Eve        : {cfg['eve_path']}")
    print(f"[{agora()}] Heartbeat a cada {HEARTBEAT_INTERVAL}s")

    if not cfg["Moon_url"]:
        print(f"[{agora()}] ERRO: URL nao configurada."); sys.exit(1)
    if not os.path.exists(cfg["eve_path"]):
        print(f"[{agora()}] ERRO: eve.json nao encontrado: {cfg['eve_path']}"); sys.exit(1)

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        print(f"[{agora()}] Autenticando como {cfg['Moon_usuario']}...")
        ok = _autenticar(cfg)
        print(f"[{agora()}] Login {'OK' if ok else 'FALHOU'}")
    else:
        print(f"[{agora()}] Sem credenciais — modo sem autenticacao")

    with _stats_lock: _stats["rodando"] = True

    def _hb_log():
        while True:
            time.sleep(60)
            with _stats_lock:
                s=_stats["seen"]; e=_stats["sent"]; er=_stats["erros"]
                hb=_stats["heartbeats"]; lo=_stats["login_ok"]; st=_stats["ultimo_status"]
            print(f"[{agora()}] stats | vistos={s} | enviados={e} | erros={er} | "
                  f"heartbeats={hb} | login={'ok' if lo else 'falhou'} | http={st}", flush=True)

    threading.Thread(target=_hb_log, daemon=True).start()

    try: _loop_sensor(cfg)
    except KeyboardInterrupt:
        print(f"\n[{agora()}] Encerrado."); sys.exit(0)