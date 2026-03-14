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
# ANIMAÇÃO ESPACIAL — Lua azul com crateras + escudo elíptico + asteroides
# ══════════════════════════════════════════════════════════════════════════════

_ANIM_W = 52
_ANIM_H = 20   # deve bater com o número de left_rows no display

_MOON_CX = _ANIM_W // 2
_MOON_CY = _ANIM_H // 2
_MOON_RX = 7
_MOON_RY = 4

# ── Paleta ANSI 256 cores ────────────────────────────────────────────────────
_C = {
    'reset':    '\033[0m',
    'dim':      '\033[38;5;238m',
    'star':     '\033[38;5;67m',
    # Lua — degradê azul (borda clara → interior médio → lado escuro)
    'moon_rim': '\033[38;5;153m',   # borda iluminada — azul claro
    'moon_lit': '\033[38;5;117m',   # face iluminada — azul médio
    'moon_mid': '\033[38;5;74m',    # face média — azul neutro
    'moon_drk': '\033[38;5;25m',    # lado escuro — azul escuro
    'crater':   '\033[38;5;24m',    # crateras — azul profundo
    # Escudo — ciano elétrico em 3 camadas
    'shield':   '\033[38;5;87m',    # camada central — ciano brilhante
    'shield_b': '\033[38;5;123m',   # pulso máximo — ciano branco
    'shield_o': '\033[38;5;24m',    # camada externa — ciano escuro
    'shield_i': '\033[38;5;51m',    # camada interna — ciano elétrico
    # Asteroides e impactos
    'ast':      '\033[38;5;214m',   # laranja
    'hit':      '\033[38;5;196m',   # vermelho vivo
    'spark':    '\033[38;5;226m',   # amarelo brilhante
    'spark2':   '\033[38;5;202m',   # laranja-fogo
    # UI
    'ok':       '\033[38;5;84m',
    'warn':     '\033[38;5;214m',
    'err':      '\033[38;5;196m',
    'neon':     '\033[38;5;87m',
    'titulo':   '\033[38;5;75m',
    'normal':   '\033[38;5;252m',
}

# ── Crateras da lua (posição relativa ao centro) ─────────────────────────────
_CRATERS = [
    # (dx, dy, rx, ry)  — coordenadas no espaço da lua, ry ajustado pelo aspect
    ( 2.5, -1.5, 1.8, 0.85),
    (-2.8,  1.2, 1.4, 0.65),
    ( 3.2,  1.8, 1.0, 0.50),
    (-1.0, -2.5, 0.8, 0.38),
    ( 0.5,  2.2, 0.7, 0.32),
    (-3.5, -1.0, 0.9, 0.42),
]

def _moon_zone(r: int, c: int):
    """
    Retorna zona da lua ou None.
    Zonas: 'rim', 'lit', 'mid', 'dark', 'crater_edge', 'crater_fill', None
    """
    dx = c - _MOON_CX
    dy = r - _MOON_CY
    # Aspect ratio do terminal (~2:1 largura:altura por char)
    ex = dx / _MOON_RX
    ey = (dy * 1.9) / _MOON_RY  # corrige aspect
    dist2 = ex * ex + ey * ey
    if dist2 > 1.0:
        return None

    # Verifica crateras primeiro
    for (cdx, cdy, crx, cry) in _CRATERS:
        ex2 = (dx - cdx) / crx
        ey2 = ((dy * 1.9) - cdy) / cry
        d2  = ex2 * ex2 + ey2 * ey2
        if d2 <= 1.0:
            return 'crater_edge' if d2 >= 0.55 else 'crater_fill'

    # Terminator suave: dx positivo = lado escuro
    norm_x = dx / _MOON_RX   # -1..+1
    if dist2 >= 0.88:
        return 'rim'
    if norm_x > 0.35:
        return 'dark'
    if norm_x > 0.05:
        return 'mid'
    return 'lit'

# Textura pre-calculada para a lua (estática)
_rng_moon = random.Random(42)
_MOON_TEXTURE: dict[tuple, tuple] = {}  # (r,c) -> (ch, color_key)

_MOON_ZONE_CHARS = {
    'rim':          (['(', ')', '|', '/', '\\', ';'],  'moon_rim'),
    'lit':          (['.', ':', '·', ' ', ' ', ' '],   'moon_lit'),
    'mid':          (['.', ' ', ' ', ' '],              'moon_mid'),
    'dark':         ([' ', ' ', '`', '.'],              'moon_drk'),
    'crater_edge':  (['(', ')', '.', ':', ';'],         'crater'),
    'crater_fill':  (['.', ' ', ' '],                   'moon_drk'),
}

for _r in range(_ANIM_H):
    for _c in range(_ANIM_W):
        _z = _moon_zone(_r, _c)
        if _z:
            _chars, _col = _MOON_ZONE_CHARS[_z]
            _MOON_TEXTURE[(_r, _c)] = (_rng_moon.choice(_chars), _col)

_MOON_CELLS = set(_MOON_TEXTURE.keys())

# ── Escudo elíptico multicamada ──────────────────────────────────────────────
_SHIELD_RX = _MOON_RX + 5
_SHIELD_RY = _MOON_RY + 3

def _build_shield():
    """Escudo elíptico com 3 camadas: inner · mid · outer."""
    cells = {}
    for r in range(_ANIM_H):
        for c in range(_ANIM_W):
            dx   = (c - _MOON_CX) / _SHIELD_RX
            dy   = (r - _MOON_CY) / _SHIELD_RY
            dist = dx * dx + dy * dy
            if   0.78 <= dist < 0.88:  cells[(r, c)] = 'inner'
            elif 0.88 <= dist < 0.97:  cells[(r, c)] = 'mid'
            elif 0.97 <= dist < 1.08:  cells[(r, c)] = 'outer'
    return cells

_SHIELD_CELLS_MAP = _build_shield()
_SHIELD_CELLS     = set(_SHIELD_CELLS_MAP.keys())

def _shield_char(r: int, c: int) -> str:
    zone  = _SHIELD_CELLS_MAP.get((r, c), 'mid')
    top   = (r - 1, c) in _SHIELD_CELLS
    bot   = (r + 1, c) in _SHIELD_CELLS
    left  = (r, c - 1) in _SHIELD_CELLS
    right = (r, c + 1) in _SHIELD_CELLS

    if right and bot and not top  and not left:  return '╔'
    if left  and bot and not top  and not right: return '╗'
    if right and top and not bot  and not left:  return '╚'
    if left  and top and not bot  and not right: return '╝'
    if left  and right and not top and not bot:
        return '═' if zone == 'mid' else ('─' if zone == 'outer' else '·')
    if top and bot and not left and not right:
        return '║' if zone == 'mid' else ('│' if zone == 'outer' else '·')
    if zone == 'inner': return '·'
    if zone == 'outer': return '°'
    return '·'

# ── Lua pequena orbitando ────────────────────────────────────────────────────
_ORBIT_RX = _SHIELD_RX - 3
_ORBIT_RY = _SHIELD_RY - 1
_MINI_RX  = 2
_MINI_RY  = 1

def _mini_moon_cells(angle_deg: float) -> dict:
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
                d  = ex * ex + ey * ey
                if d <= 1.0:
                    cells[(r, c)] = 'edge' if d >= 0.45 else 'fill'
    return cells

_rng_mini          = random.Random(99)
_MINI_TEXTURE_EDGE = _rng_mini.choice(['o', '°', 'O'])
_MINI_TEXTURE_FILL = _rng_mini.choice(['.', '·', ' '])

# ── Estrelas de fundo ────────────────────────────────────────────────────────
_rng_stars  = random.Random(7)
_occupied   = _SHIELD_CELLS | _MOON_CELLS
_STAR_POSITIONS: list[tuple] = []
for _attempt in range(800):
    _sr = _rng_stars.randint(0, _ANIM_H - 1)
    _sc = _rng_stars.randint(0, _ANIM_W - 1)
    if (_sr, _sc) not in _occupied and len(_STAR_POSITIONS) < 30:
        _STAR_POSITIONS.append((_sr, _sc, _rng_stars.choice(['·', '.', '*', '\'', '+'])))

# ── Estado da animação ───────────────────────────────────────────────────────
_anim_state = {
    "asteroids":   [],
    "sparks":      [],
    "tick":        0,
    "orbit_angle": 0.0,
}

def _anim_tick():
    st = _anim_state
    st["tick"] += 1
    t = st["tick"]

    # Lua pequena orbita a cada ~200 ticks
    st["orbit_angle"] = (st["orbit_angle"] + 1.8) % 360

    # Spawna asteroide a cada ~25 ticks, máx 5 simultâneos
    if t % 25 == 0 and len(st["asteroids"]) < 5:
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
            if a['blink'] < 10:
                next_asts.append(a)
            continue
        nc = a['c'] + a['dc']
        nr = a['r']
        if nc < 0 or nc >= _ANIM_W:
            continue
        if (nr, nc) in _SHIELD_CELLS or (nr, nc) in _MOON_CELLS:
            # Impacto — spawna faíscas em 8 direções + diagonais
            for dr, dc2 in [(-1,0),(1,0),(0,-1),(0,1),(-1,-1),(-1,1),(1,-1),(1,1),(0,-2),(0,2)]:
                sr2, sc2 = a['r'] + dr, a['c'] + dc2
                if 0 <= sr2 < _ANIM_H and 0 <= sc2 < _ANIM_W:
                    st["sparks"].append({
                        'r': sr2, 'c': sc2, 'age': 0,
                        'ch':  random.choice(['*', '·', '°', '`', '\'', '+', 'x']),
                        'col': random.choice(['spark', 'spark2', 'hit']),
                    })
            a['blocked'] = True
            a['blink']   = 0
            next_asts.append(a)
        else:
            a['c'] = nc
            next_asts.append(a)
    st["asteroids"] = next_asts

    st["sparks"] = [s for s in st["sparks"] if s['age'] < 9]
    for s in st["sparks"]:
        s['age'] += 1


def _render_space_lines() -> list[str]:
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

    # Grid: cada célula é (char, color_key)
    grid = [[(' ', 'dim')] * _ANIM_W for _ in range(_ANIM_H)]

    # 1. Estrelas
    for sr, sc, sch in _STAR_POSITIONS:
        grid[sr][sc] = (sch, 'star')

    # 2. Escudo multicamada
    for (r, c), zone in _SHIELD_CELLS_MAP.items():
        grid[r][c] = (_shield_char(r, c), shield_colors.get(zone, 'shield'))

    # 3. Lua com textura e crateras
    for (r, c), (ch, col) in _MOON_TEXTURE.items():
        grid[r][c] = (ch, col)

    # 4. Lua pequena orbitando
    mini_cells = _mini_moon_cells(st["orbit_angle"])
    for (r, c), zone in mini_cells.items():
        if (r, c) not in _MOON_CELLS and (r, c) not in _SHIELD_CELLS:
            grid[r][c] = (
                _MINI_TEXTURE_EDGE if zone == 'edge' else _MINI_TEXTURE_FILL,
                'spark' if zone == 'edge' else 'moon_lit',
            )

    # 5. Asteroides
    for a in st["asteroids"]:
        r, c = a['r'], a['c']
        if 0 <= r < _ANIM_H and 0 <= c < _ANIM_W:
            if a['blocked']:
                if a['blink'] % 2 == 0:
                    grid[r][c] = ('X', 'hit')
            else:
                grid[r][c] = (a['ch'], 'ast')

    # 6. Faíscas de impacto
    for s in st["sparks"]:
        r, c = s['r'], s['c']
        if 0 <= r < _ANIM_H and 0 <= c < _ANIM_W:
            # Faíscas mais antigas ficam mais apagadas
            col = s['col'] if s['age'] < 5 else 'dim'
            grid[r][c] = (s['ch'], col)

    # Renderiza linhas com ANSI
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

def _alt_screen_enter() -> str:
    return "\033[?1049h"

def _alt_screen_exit() -> str:
    return "\033[?1049l"

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

    sys.stdout.write(_alt_screen_enter())
    sys.stdout.write(_hide_cursor())
    sys.stdout.flush()

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        sys.stdout.write("\033[2J\033[H")
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
        sys.stdout.write(_show_cursor())
        sys.stdout.write(_alt_screen_exit())
        sys.stdout.flush()


# ══════════════════════════════════════════════════════════════════════════════
# LOOP DE DISPLAY — tela alternativa, redesenho total a cada frame
# ══════════════════════════════════════════════════════════════════════════════

_SPIN = ['◐', '◓', '◑', '◒']

_LEFT_W  = 36
_RIGHT_W = _ANIM_W + 2

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

        W = _LEFT_W

        def _row(txt, cor=C_DIM):
            return (txt, cor)

        def _box(content, cor=C_DIM):
            inner = content[:W - 4]
            return _row(f"║  {inner:<{W-4}}║", cor)

        def _sep(l='╠', r='╣'):
            return _row(l + '═' * (W - 2) + r, C_DIM)

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

        while len(left_rows) < _ANIM_H:
            left_rows.append(_row('║' + ' ' * (W - 2) + '║', C_DIM))
        left_rows = left_rows[:_ANIM_H]

        right_rows = _render_space_lines()

        frame_lines = []
        for (ltxt, lcor), rline in zip(left_rows, right_rows):
            left_part  = '\033[2K' + lcor + ltxt + RESET
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