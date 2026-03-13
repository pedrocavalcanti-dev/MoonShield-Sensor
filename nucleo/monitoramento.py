import os
import math
import time
import json
import random
import threading
import requests

from nucleo.configuracao import TIPOS_ACEITOS, salvar_config
from nucleo.utilitarios import agora

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO GLOBAL DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

_stats = {
    "seen":          0,
    "sent":          0,
    "erros":         0,
    "buffer":        0,
    "ultimo":        "—",
    "rodando":       False,
    "heartbeats":    0,
    "login_ok":      False,
    "ultimo_status": "—",
}
_stats_lock = threading.Lock()

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
# CURSOR — persiste posição no eve.json
# ══════════════════════════════════════════════════════════════════════════════

def _cursor_path(eve_path: str) -> str:
    return eve_path + ".moonshield.cursor"

def _ler_cursor(eve_path: str):
    try:
        with open(_cursor_path(eve_path), "r") as f:
            return int(f.read().strip())
    except Exception:
        return None

def _salvar_cursor(eve_path: str, pos: int):
    try:
        with open(_cursor_path(eve_path), "w") as f:
            f.write(str(pos))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# ANIMAÇÃO ESPACIAL
# ══════════════════════════════════════════════════════════════════════════════

_ANIM_W = 52
_ANIM_H = 20   # deve bater com o número de left_rows no display

_MOON_CX = _ANIM_W // 2
_MOON_CY = _ANIM_H // 2
_MOON_RX = 7
_MOON_RY = 4

def _build_moon():
    cells = {}
    for r in range(_ANIM_H):
        for c in range(_ANIM_W):
            dx   = (c - _MOON_CX) / _MOON_RX
            dy   = (r - _MOON_CY) / _MOON_RY
            dist = dx*dx + dy*dy
            if dist <= 1.0:
                cells[(r, c)] = 'edge' if dist >= 0.70 else 'fill'
    return cells

_MOON_CELLS = _build_moon()

_rng_moon = random.Random(42)
_MOON_TEXTURE = {}
for _pos, _zone in _MOON_CELLS.items():
    if _zone == 'edge':
        _MOON_TEXTURE[_pos] = _rng_moon.choice(['(', ')', '.', ':', ';', '|'])
    else:
        _MOON_TEXTURE[_pos] = _rng_moon.choice(['.', ':', '·', ' ', ' ', ' ', ' '])

_SHIELD_RX = _MOON_RX + 5
_SHIELD_RY = _MOON_RY + 3

def _build_shield():
    """Escudo elíptico com 3 camadas: inner · mid · outer."""
    cells = {}
    for r in range(_ANIM_H):
        for c in range(_ANIM_W):
            dx   = (c - _MOON_CX) / _SHIELD_RX
            dy   = (r - _MOON_CY) / _SHIELD_RY
            dist = dx*dx + dy*dy
            if   0.78 <= dist < 0.88:  cells[(r, c)] = 'inner'
            elif 0.88 <= dist < 0.97:  cells[(r, c)] = 'mid'
            elif 0.97 <= dist < 1.08:  cells[(r, c)] = 'outer'
    return cells

_SHIELD_CELLS_MAP = _build_shield()
_SHIELD_CELLS     = set(_SHIELD_CELLS_MAP.keys())

# Paleta de energia do escudo — pisca suavemente em 2 tons
_SHIELD_ENERGY = [
    '\033[38;5;87m',   # ciano brilhante
    '\033[38;5;51m',   # ciano elétrico
    '\033[38;5;45m',   # azul-ciano
]

def _shield_char(r, c):
    zone  = _SHIELD_CELLS_MAP.get((r, c), 'mid')
    top   = (r-1, c)   in _SHIELD_CELLS
    bot   = (r+1, c)   in _SHIELD_CELLS
    left  = (r,   c-1) in _SHIELD_CELLS
    right = (r,   c+1) in _SHIELD_CELLS

    if right and bot and not top and not left:   return '╔'
    if left  and bot and not top and not right:  return '╗'
    if right and top and not bot and not left:   return '╚'
    if left  and top and not bot and not right:  return '╝'
    if left and right and not top and not bot:
        return '═' if zone == 'mid' else ('─' if zone == 'outer' else '·')
    if top and bot and not left and not right:
        return '║' if zone == 'mid' else ('│' if zone == 'outer' else '·')
    # diagonal / curva → pontos de energia que piscam
    if zone == 'inner': return '·'
    if zone == 'outer': return '°'
    return '·'

# ── Lua pequena dentro do escudo (órbita animada) ────────────────────────────
_ORBIT_RX = _SHIELD_RX - 3
_ORBIT_RY = _SHIELD_RY - 1
_MINI_RX  = 2
_MINI_RY  = 1

def _mini_moon_cells(angle_deg: float):
    import math
    angle = math.radians(angle_deg)
    ocx   = _MOON_CX + _ORBIT_RX * math.cos(angle)
    ocy   = _MOON_CY + _ORBIT_RY * math.sin(angle)
    cells = {}
    for dr in range(-_MINI_RY - 1, _MINI_RY + 2):
        for dc in range(-_MINI_RX - 1, _MINI_RX + 2):
            r = int(round(ocy)) + dr
            c = int(round(ocx)) + dc
            if 0 <= r < _ANIM_H and 0 <= c < _ANIM_W:
                ex = (c - ocx) / _MINI_RX
                ey = (r - ocy) / _MINI_RY
                d  = ex*ex + ey*ey
                if d <= 1.0:
                    cells[(r, c)] = 'edge' if d >= 0.45 else 'fill'
    return cells

_rng_mini          = random.Random(99)
_MINI_TEXTURE_EDGE = _rng_mini.choice(['o', '°', 'O'])
_MINI_TEXTURE_FILL = _rng_mini.choice(['.', '·', ' '])

_rng_stars      = random.Random(7)
_occupied       = _SHIELD_CELLS | set(_MOON_CELLS.keys())
_STAR_POSITIONS = []
for _attempt in range(800):
    _sr = _rng_stars.randint(0, _ANIM_H - 1)
    _sc = _rng_stars.randint(0, _ANIM_W - 1)
    if (_sr, _sc) not in _occupied and len(_STAR_POSITIONS) < 30:
        _STAR_POSITIONS.append((_sr, _sc, _rng_stars.choice(['·', '.', '*', '\'', '+'])))

_anim_state = {
    "asteroids":   [],
    "sparks":      [],
    "tick":        0,
    "orbit_angle": 0.0,   # graus — lua pequena orbita dentro do escudo
}

def _anim_is_moon(r, c):
    return (r, c) in _MOON_CELLS

def _anim_tick():
    st = _anim_state
    st["tick"] += 1
    t = st["tick"]
    # Lua pequena dá uma volta completa a cada ~200 ticks (~36s)
    st["orbit_angle"] = (st["orbit_angle"] + 1.8) % 360

    if t % 25 == 0 and len(st["asteroids"]) < 4:
        side = random.choice(['L', 'R'])
        r    = random.randint(0, _ANIM_H - 1)
        c    = 0 if side == 'L' else _ANIM_W - 1
        dc   = 1 if side == 'L' else -1
        st["asteroids"].append({
            'r': r, 'c': c, 'dc': dc,
            'ch': random.choice(['*', '#', '@', '%', '+']),
            'blocked': False, 'blink': 0,
        })

    next_asts = []
    for a in st["asteroids"]:
        if a['blocked']:
            a['blink'] += 1
            if a['blink'] < 8:
                next_asts.append(a)
            continue
        nc = a['c'] + a['dc']
        nr = a['r']
        if nc < 0 or nc >= _ANIM_W:
            continue
        if (nr, nc) in _SHIELD_CELLS or _anim_is_moon(nr, nc):
            for dr, dc2 in [(-1,0),(1,0),(0,-1),(0,1),(-1,-1),(-1,1),(1,-1),(1,1)]:
                sr2, sc2 = a['r']+dr, a['c']+dc2
                if 0 <= sr2 < _ANIM_H and 0 <= sc2 < _ANIM_W:
                    st["sparks"].append({
                        'r': sr2, 'c': sc2, 'age': 0,
                        'ch': random.choice(['*', '·', '°', '`', '\''])
                    })
            a['blocked'] = True
            a['blink']   = 0
            next_asts.append(a)
        else:
            a['c'] = nc
            next_asts.append(a)
    st["asteroids"] = next_asts

    st["sparks"] = [s for s in st["sparks"] if s['age'] < 8]
    for s in st["sparks"]:
        s['age'] += 1

_C = {
    'reset':    '\033[0m',
    'dim':      '\033[38;5;238m',
    'star':     '\033[38;5;67m',
    'moon_e':   '\033[38;5;153m',
    'moon_f':   '\033[38;5;117m',
    'shield':   '\033[38;5;87m',      # ciano brilhante — camada central
    'shield_b': '\033[38;5;123m',     # ciano muito brilhante — pulso máximo
    'shield_o': '\033[38;5;24m',      # ciano escuro — camada externa
    'shield_i': '\033[38;5;51m',      # ciano elétrico — camada interna
    'ast':      '\033[38;5;214m',
    'hit':      '\033[38;5;196m',
    'spark':    '\033[38;5;226m',
    'ok':       '\033[38;5;84m',
    'warn':     '\033[38;5;214m',
    'err':      '\033[38;5;196m',
    'neon':     '\033[38;5;87m',
    'titulo':   '\033[38;5;75m',
    'normal':   '\033[38;5;252m',
}

def _render_space_lines() -> list:
    _anim_tick()
    st   = _anim_state
    tick = st["tick"]

    # Escudo pulsa entre 3 tons a cada 8 ticks
    pulse = (tick // 8) % 3
    shield_colors = {
        'outer': ['shield_o', 'shield_o', 'shield'  ][pulse],
        'mid':   ['shield',   'shield_b', 'shield'  ][pulse],
        'inner': ['shield_i', 'shield',   'shield_i'][pulse],
    }

    grid = [[(' ', 'dim')] * _ANIM_W for _ in range(_ANIM_H)]

    for sr, sc, sch in _STAR_POSITIONS:
        grid[sr][sc] = (sch, 'star')

    # Escudo multicamada com pulso de energia
    for (r, c), zone in _SHIELD_CELLS_MAP.items():
        grid[r][c] = (_shield_char(r, c), shield_colors.get(zone, 'shield'))

    for (r, c), zone in _MOON_CELLS.items():
        ch  = _MOON_TEXTURE[(r, c)]
        cls = 'moon_e' if zone == 'edge' else 'moon_f'
        grid[r][c] = (ch, cls)

    # Lua pequena orbitando dentro do escudo
    mini_cells = _mini_moon_cells(st["orbit_angle"])
    for (r, c), zone in mini_cells.items():
        if (r, c) not in _MOON_CELLS and (r, c) not in _SHIELD_CELLS:
            grid[r][c] = (_MINI_TEXTURE_EDGE if zone == 'edge' else _MINI_TEXTURE_FILL,
                          'spark' if zone == 'edge' else 'moon_e')

    for a in st["asteroids"]:
        r, c = a['r'], a['c']
        if 0 <= r < _ANIM_H and 0 <= c < _ANIM_W:
            if a['blocked']:
                if a['blink'] % 2 == 0:
                    grid[r][c] = ('X', 'hit')
            else:
                grid[r][c] = (a['ch'], 'ast')

    for s in st["sparks"]:
        r, c = s['r'], s['c']
        if 0 <= r < _ANIM_H and 0 <= c < _ANIM_W:
            grid[r][c] = (s['ch'], 'spark')

    lines = []
    for row in grid:
        line     = ""
        prev_cls = None
        for ch, cls in row:
            if cls != prev_cls:
                line    += _C['reset'] + _C.get(cls, '')
                prev_cls = cls
            line += ch
        line += _C['reset']
        lines.append(line)
    return lines


# ══════════════════════════════════════════════════════════════════════════════
# ANSI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _hide_cursor() -> str:
    return "\033[?25l"

def _show_cursor() -> str:
    return "\033[?25h"

# Tela alternativa: entra/sai sem afetar o histórico do terminal
def _alt_screen_enter() -> str:
    return "\033[?1049h"

def _alt_screen_exit() -> str:
    return "\033[?1049l"

# Move cursor para home (1,1) sem limpar — depois sobrescrevemos cada linha
def _home() -> str:
    return "\033[H"

def _enable_ansi_windows():
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32          # type: ignore
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# TELA DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

def tela_sensor(cfg: dict):
    from nucleo.interface import (
        cabecalho, print_resultado, linha_vazia,
        linha_texto, aguardar_enter, limpar, C_DIM,
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

    with _stats_lock:
        _stats["seen"]          = 0
        _stats["sent"]          = 0
        _stats["erros"]         = 0
        _stats["buffer"]        = 0
        _stats["ultimo"]        = "—"
        _stats["heartbeats"]    = 0
        _stats["login_ok"]      = False
        _stats["rodando"]       = True
        _stats["ultimo_status"] = "—"

    _anim_state["asteroids"]   = []
    _anim_state["sparks"]      = []
    _anim_state["tick"]        = 0
    _anim_state["orbit_angle"] = 0.0

    _enable_ansi_windows()

    import sys

    # Entra na tela alternativa — o histórico do terminal fica intacto
    sys.stdout.write(_alt_screen_enter())
    sys.stdout.write(_hide_cursor())
    sys.stdout.flush()

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        sys.stdout.write("\033[2J\033[H")   # limpa só dentro da alt screen
        sys.stdout.write(f"  Autenticando como {cfg['Moon_usuario']}...\n")
        sys.stdout.flush()
        ok = _autenticar(cfg)
        sys.stdout.write("  ✔ Login OK\n" if ok else "  ✗ Login falhou — continuando sem autenticação\n")
        sys.stdout.flush()
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
        # Sai da tela alternativa → terminal volta exatamente como estava
        sys.stdout.write(_show_cursor())
        sys.stdout.write(_alt_screen_exit())
        sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# LOOP DE DISPLAY — tela alternativa, redesenho total a cada frame
# ══════════════════════════════════════════════════════════════════════════════

_SPIN = ['◐', '◓', '◑', '◒']

# Largura da coluna esquerda (texto) e direita (animação)
_LEFT_W  = 36   # chars de conteúdo
_RIGHT_W = _ANIM_W + 2  # +2 de padding

def _loop_display(cfg: dict):
    import sys

    RESET    = '\033[0m'
    C_TITULO = '\033[38;5;75m'
    C_DIM    = '\033[38;5;238m'
    C_NORMAL = '\033[38;5;252m'
    C_OK     = '\033[38;5;84m'
    C_ERRO   = '\033[38;5;196m'
    C_AVISO  = '\033[38;5;214m'
    C_NEON   = '\033[38;5;87m'

    idx = 0

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
            lo     = _stats["login_ok"]
            us     = _stats["ultimo_status"]

        usuario   = cfg.get("Moon_usuario", "")
        login_str = (f"✔ {usuario}" if lo
                     else ("✗ nao autenticado" if usuario else "— sem credenciais"))
        login_cor = C_OK if lo else (C_ERRO if usuario else C_DIM)

        if buf > 0:
            spin_txt = f"[ ▶ ]  enviando {buf} eventos..."
            spin_cor = C_AVISO
        elif erros > 0 and us not in ("HTTP 200", "—"):
            spin_txt = f"[ ✗ ]  erro: {us}"
            spin_cor = C_ERRO
        else:
            spin_txt = f"[{_SPIN[idx % 4]}]  escudo ativo"
            spin_cor = C_NEON

        # ── Coluna esquerda ───────────────────────────────────────────────────
        # IMPORTANTE: o número de itens DEVE ser igual a _ANIM_H (20 linhas)
        # para que a animação direita nunca seja cortada nem sobre linhas vazias.
        W = _LEFT_W   # alias curto

        def _row(txt, cor=C_DIM):
            return (txt, cor)

        def _box(content, cor=C_DIM):
            inner = content[:W - 4]
            return _row(f"║  {inner:<{W-4}}║", cor)

        def _sep(l='╠', r='╣'):
            return _row(l + '═' * (W - 2) + r, C_DIM)

        # Bloco de stats — preenche com linhas até bater _ANIM_H
        left_rows = [
            _row('╔' + '═' * (W - 2) + '╗',                  C_DIM),      # 1
            _box('MOONSHIELD — SENSOR ATIVO',                  C_TITULO),   # 2
            _sep(),                                                           # 3
            _box(f"URL    : {cfg['Moon_url']}",                C_DIM),      # 4
            _box(f"Sensor : {cfg['sensor_nome']}",             C_DIM),      # 5
            _box(f"Login  : {login_str}",                      login_cor),  # 6
            _box(f"Eve    : {cfg['eve_path']}",                C_DIM),      # 7
            _sep(),                                                           # 8
            _box(spin_txt,                                     spin_cor),   # 9
            _sep(),                                                           # 10
            _box(f"Vistos    : {seen:,}",                      C_NORMAL),   # 11
            _box(f"Enviados  : {sent:,}",                      C_OK),       # 12
            _box(f"Erros     : {erros:,}",  C_ERRO if erros else C_DIM),   # 13
            _box(f"Buffer    : {buf}",                         C_DIM),      # 14
            _box(f"Heartbeat : {hb}",                          C_DIM),      # 15
            _box(f"Último    : {ultimo}",                      C_DIM),      # 16
            _box(f"HTTP      : {us}",                          C_DIM),      # 17
            _sep(),                                                           # 18
            _box('Ctrl+C para parar',                          C_DIM),      # 19
            _row('╚' + '═' * (W - 2) + '╝',                  C_DIM),      # 20
        ]
        # Garante exatamente _ANIM_H linhas (20), sem depender de contagem manual
        while len(left_rows) < _ANIM_H:
            left_rows.append(_row('║' + ' ' * (W - 2) + '║', C_DIM))
        left_rows = left_rows[:_ANIM_H]

        # ── Coluna direita: animação (sempre _ANIM_H linhas) ─────────────────
        right_rows = _render_space_lines()

        # ── Monta frame ───────────────────────────────────────────────────────
        frame_lines = []
        for (ltxt, lcor), rline in zip(left_rows, right_rows):
            # Linha esquerda (largura fixa, sem ANSI)
            left_part  = '\033[2K' + lcor + ltxt + RESET
            # Linha direita (já tem ANSI embutido)
            right_part = '  ' + rline
            frame_lines.append(left_part + right_part)

        frame = _home() + "\n".join(frame_lines)
        sys.stdout.write(frame)
        sys.stdout.flush()

        idx += 1
        time.sleep(0.18)


# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL DO SENSOR
# ══════════════════════════════════════════════════════════════════════════════

HEARTBEAT_INTERVAL    = 15
DEFAULT_BATCH_TIMEOUT = 2
REAUTH_INTERVAL       = 3600


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
        cursor_salvo = _ler_cursor(eve_path)
        f.seek(cursor_salvo if cursor_salvo is not None else 0)

        while True:
            with _stats_lock:
                if not _stats["rodando"]:
                    break

            if time.time() - last_reauth >= REAUTH_INTERVAL:
                _autenticar(cfg)
                last_reauth = time.time()

            line = f.readline()

            if not line:
                agora_ts          = time.time()
                tempo_desde_envio = agora_ts - last_send

                if buffer and tempo_desde_envio >= batch_timeout:
                    ok  = _enviar(ingest_url, sensor_nome, buffer, cfg)
                    pos = f.tell()
                    with _stats_lock:
                        if ok:
                            _stats["sent"]  += len(buffer)
                            _stats["ultimo"] = agora()
                            _salvar_cursor(eve_path, pos)
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
                ok  = _enviar(ingest_url, sensor_nome, buffer, cfg)
                pos = f.tell()
                with _stats_lock:
                    if ok:
                        _stats["sent"]  += len(buffer)
                        _stats["ultimo"] = agora()
                        _salvar_cursor(eve_path, pos)
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
        headers = {
            "Content-Type": "application/json",
            "X-MS-TOKEN":   cfg.get("token", ""),
        }
        with _session_lock:
            resp = _session.post(url, json=payload, timeout=5, headers=headers)

        status_str = f"HTTP {resp.status_code}"
        with _stats_lock:
            _stats["ultimo_status"] = status_str

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
            data       = resp.json()
            token_novo = data.get("token", "")
            if token_novo and token_novo != cfg.get("token", ""):
                cfg["token"] = token_novo
                salvar_config(cfg)
        except Exception:
            pass

        return True

    except requests.exceptions.ConnectionError:
        with _stats_lock:
            _stats["ultimo_status"] = "CONN ERR"
        return False
    except Exception as e:
        with _stats_lock:
            _stats["ultimo_status"] = f"ERR: {str(e)[:30]}"
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

    _anim_state["asteroids"]   = []
    _anim_state["sparks"]      = []
    _anim_state["tick"]        = 0
    _anim_state["orbit_angle"] = 0.0

    with _stats_lock:
        _stats["rodando"] = True

    def heartbeat_log():
        while True:
            time.sleep(60)
            with _stats_lock:
                s      = _stats["seen"]
                e      = _stats["sent"]
                er     = _stats["erros"]
                hb     = _stats["heartbeats"]
                lo     = _stats["login_ok"]
                status = _stats["ultimo_status"]
            print(
                f"[{agora()}] stats | vistos={s} | enviados={e} | "
                f"erros={er} | heartbeats={hb} | "
                f"login={'ok' if lo else 'falhou'} | ultimo_http={status}",
                flush=True,
            )

    threading.Thread(target=heartbeat_log, daemon=True).start()

    try:
        _loop_sensor(cfg)
    except KeyboardInterrupt:
        print(f"\n[{agora()}] MoonShield Sensor encerrado.")
        sys.exit(0)