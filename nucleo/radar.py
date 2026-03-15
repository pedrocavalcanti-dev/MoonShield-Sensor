#!/usr/bin/env python3
"""
nucleo/radar.py - Motor do radar ASCII. Importado por monitoramento.py.
Standalone: python3 -m nucleo.radar
"""
import math, time, random, sys, termios, tty, threading

# ══════════════════════════════════════════════════════════════════════════════
# DIMENSÕES
# ══════════════════════════════════════════════════════════════════════════════
W=63; H=29; CX=W//2; CY=H//2
AY=0.48
RADIUS=min(CX,CY-1)

SWEEP_DEG  = 4.5
TRAIL_DEG  = 80
TRAIL_LVL  = 8
PING_LIFE  = 20   # morre mais rápido — radar fica limpo
PING_CHARS = ['+','x','*','●','◆']
NOISE_LIFE = 4
WAVE_MAX   = 2
WAVE_LIFE  = 6

# Máximo de pings simultâneos no radar — mesmo com muitos eventos, não loteia
_PING_MAX  = 8

# ══════════════════════════════════════════════════════════════════════════════
# PALETA
# ══════════════════════════════════════════════════════════════════════════════
_R = '\033[0m'
def _fg(n): return f'\033[38;5;{n}m'
def _bg(n): return f'\033[48;5;{n}m'

SWEEP_PAL = [_fg(82),_fg(46),_fg(40),_fg(34),_fg(28),_fg(22),_fg(237),_fg(235)]
PING_PAL  = [_fg(226),_fg(220),_fg(214),_fg(208),_fg(166),_fg(130),_fg(237)]
WAVE_PAL  = [_fg(51),_fg(45),_fg(39),_fg(33),_fg(27),_fg(237)]

C_RING_O  = _fg(22)
C_RING_M  = _fg(28)
C_RING_I  = _fg(34)
C_CROSS   = _fg(22)
C_CENTER  = _fg(46)
C_EDGE_O  = _fg(46)
C_EDGE_I  = _fg(40)
C_OUT     = _fg(232)
C_BG_IN   = _fg(232)  # preto limpo dentro do círculo (igual fora)
C_NOISE   = _fg(234)
C_DIM     = _fg(238)
C_NAME    = _fg(40)
C_TAG     = _fg(28)
C_HUD     = _fg(238)
C_HUD_V   = _fg(34)

# ══════════════════════════════════════════════════════════════════════════════
# NOME ASCII — P.Cavalcanti, 4 linhas, max 50 chars, P com curva fechada
# ══════════════════════════════════════════════════════════════════════════════
_NAME_ART = [
    r" ___    ___               _             _   _ ",
    r"| _ \  / __|__ ___ ____ _| |__ __ _ _ _| |_(_)",
    r"|  _/ | (__/ _` \ V / _` | / _/ _` | ' \  _| |",
    r"|_|    \___\__,_|\_/\__,_|_\__\__,_|_||_\__|_|",
]

def _center(s, width):
    pad = max(0, (width - len(s)) // 2)
    return ' ' * pad + s

# ══════════════════════════════════════════════════════════════════════════════
# GEOMETRIA
# ══════════════════════════════════════════════════════════════════════════════
def _ic(r,c):
    dx=c-CX; dy=(r-CY)/AY
    return dx*dx+dy*dy<=RADIUS*RADIUS

def _dist(r,c):
    dx=c-CX; dy=(r-CY)/AY
    return math.sqrt(dx*dx+dy*dy)

def _ang(r,c):
    return math.degrees(math.atan2(c-CX,-(r-CY)))%360

def _rcol(r,c):
    d=_dist(r,c)/RADIUS
    return C_RING_O if d>0.64 else (C_RING_M if d>0.32 else C_RING_I)

_CELLS={}
for _r in range(H):
    for _c in range(W):
        if not _ic(_r,_c):
            _CELLS[(_r,_c)]='out'
        elif _r==CY and _c==CX:
            _CELLS[(_r,_c)]='ctr'
        else:
            d=_dist(_r,_c)/RADIUS
            # borda dupla: outer (0.93-1.0) e inner (0.87-0.93)
            if   d>=0.93:              _CELLS[(_r,_c)]='edge_o'
            elif d>=0.87:              _CELLS[(_r,_c)]='edge_i'
            elif abs(d-.33)<.035 or abs(d-.55)<.025 or abs(d-.77)<.025:
                                       _CELLS[(_r,_c)]='ring'
            elif _r==CY or _c==CX:    _CELLS[(_r,_c)]='cross'
            else:                      _CELLS[(_r,_c)]='fill'

_FILL=[(r,c) for (r,c),k in _CELLS.items() if k=='fill']

# Marcadores na borda: só traços verticais a cada 10°, sem números
_DEGREE_MARKS={}
for _deg in range(0,360,10):
    _a=math.radians(_deg)
    _br=RADIUS*0.97
    _rc=int(round(CY - _br*AY*math.cos(_a)))
    _cc=int(round(CX + _br*math.sin(_a)))
    if 0<=_rc<H and 0<=_cc<W:
        _DEGREE_MARKS[(_rc,_cc)]='|'

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO
# ══════════════════════════════════════════════════════════════════════════════
_st={
    "tick":0,"angle":0.0,
    "pings":[],"noise":[],"waves":[],
    "event_count":0,
}

def _tick():
    s=_st; s["tick"]+=1
    s["angle"]=(s["angle"]+SWEEP_DEG)%360
    s["pings"]=[p for p in s["pings"] if p["age"]<PING_LIFE]
    for p in s["pings"]: p["age"]+=1
    nd=min(0.012+s["event_count"]*0.001,0.04)
    s["noise"]=[n for n in s["noise"] if n["age"]<NOISE_LIFE]
    for n in s["noise"]: n["age"]+=1
    for r,c in random.sample(_FILL,min(10,len(_FILL))):
        if random.random()<nd: s["noise"].append({"r":r,"c":c,"age":0})
    s["waves"]=[w for w in s["waves"] if w["age"]<WAVE_LIFE]
    for w in s["waves"]: w["age"]+=1

def add_ping(r=None,c=None):
    # Com muitos eventos, não acumula mais que _PING_MAX pings simultâneos
    if len(_st["pings"]) >= _PING_MAX:
        _st["pings"].pop(0)   # remove o mais antigo
    ang=_st["angle"]
    if r is None:
        for _ in range(60):
            cr,cc=random.choice(_FILL)
            if (ang-_ang(cr,cc))%360<12: r,c=cr,cc; break
        else: r,c=random.choice(_FILL)
    _st["pings"].append({"r":r,"c":c,"age":0,"ch":random.choice(PING_CHARS)})
    if len(_st["waves"])<WAVE_MAX:
        _st["waves"].append({"cr":r,"cc":c,"age":0})
    _st["event_count"]+=1

# ══════════════════════════════════════════════════════════════════════════════
# HUD
# ══════════════════════════════════════════════════════════════════════════════
def _hud_top():
    az=int(_st["angle"]); cont=len(_st["pings"]); ev=_st["event_count"]
    l=f'AZ:{az:03d}\u00b0'; m=f'CONTACTS:{cont}'; rr=f'EVT:{ev}'
    g1=(W-len(l)-len(m)-len(rr))//2
    g2=W-len(l)-len(m)-len(rr)-g1
    return C_HUD+l+' '*g1+C_HUD_V+m+C_HUD+' '*g2+rr+_R

def _hud_bot():
    t=_st["tick"]
    lat=23.0+math.sin(t*0.003)*0.05; lon=41.0+math.cos(t*0.002)*0.05
    coord=f'N{abs(lat):06.3f}  E{abs(lon):06.3f}'
    l='MODE:SCAN'; rr=f'POS:{coord}'
    g=W-len(l)-len(rr)
    return C_HUD+l+' '*max(1,g)+rr+_R

# ══════════════════════════════════════════════════════════════════════════════
# RENDER
# ══════════════════════════════════════════════════════════════════════════════
def get_radar_lines():
    _tick()
    sweep=_st["angle"]
    pmap={(p["r"],p["c"]):p for p in _st["pings"]}
    nset={(n["r"],n["c"]) for n in _st["noise"]}

    wave_cells={}
    for wv in _st["waves"]:
        wr=(wv["age"]+1)*1.6; wi=wv["age"]/WAVE_LIFE
        for r in range(H):
            for c in range(W):
                if _CELLS[(r,c)] in ('fill','ring','cross','edge_i'):
                    dx=c-wv["cc"]; dy=(r-wv["cr"])/AY
                    d=math.sqrt(dx*dx+dy*dy)
                    if abs(d-wr)<1.2:
                        wave_cells[(r,c)]=max(wave_cells.get((r,c),0),1-wi)

    lines=[]
    for r in range(H):
        seg=""; pc=None
        def w(col,ch):
            nonlocal seg,pc
            if col!=pc: seg+=_R+col; pc=col
            seg+=ch
        for c in range(W):
            k=_CELLS[(r,c)]

            if k=='out':
                w(C_OUT,' '); continue

            # borda externa brilhante — com marcadores de grau
            if k=='edge_o':
                ch=_DEGREE_MARKS.get((r,c),'░')
                w(C_EDGE_O,ch); continue

            # borda interna
            if k=='edge_i':
                w(C_EDGE_I,'▒'); continue

            if k=='ctr':
                w(C_CENTER,'+'); continue

            # ping
            if (r,c) in pmap:
                p=pmap[(r,c)]
                pi=min(p["age"]*len(PING_PAL)//PING_LIFE,len(PING_PAL)-1)
                ch=p["ch"] if p["age"]%3!=1 else '·'
                w(PING_PAL[pi],ch); continue

            # onda
            if (r,c) in wave_cells:
                wi=wave_cells[(r,c)]
                wpi=min(int((1-wi)*len(WAVE_PAL)),len(WAVE_PAL)-1)
                w(WAVE_PAL[wpi],'·'); continue

            # sweep
            diff=(sweep-_ang(r,c))%360
            if diff<=TRAIL_DEG:
                lvl=int(diff/TRAIL_DEG*(TRAIL_LVL-1))
                if k=='ring':    ch='·'
                elif k=='cross': ch='─' if r==CY else '│'
                else:            ch=['█','▓','▓','▒','░','░','·',' '][lvl]
                w(SWEEP_PAL[lvl],ch); continue

            # ruído
            if (r,c) in nset: w(C_NOISE,'·'); continue

            # estrutura base
            if k=='ring':    w(_rcol(r,c),'·')
            elif k=='cross': w(C_CROSS,'─' if r==CY else '│')
            else:            w(C_BG_IN,' ')   # fundo esverdeado

        lines.append(seg+_R)
    return lines

# ══════════════════════════════════════════════════════════════════════════════
# ASSINATURA
# ══════════════════════════════════════════════════════════════════════════════
def get_signature_lines():
    sep=C_DIM+'·'*W+_R
    tl='network sensor  //  MoonShield'
    out=[sep]
    for line in _NAME_ART:
        out.append(C_NAME+_center(line,W)+_R)
    out.append(C_TAG+_center(tl,W)+_R)
    return out

# H radar + 2 HUD + 1 sep + 5 nome + 1 tagline = H+9
# mas get_signature_lines = 1+5+1 = 7, HUD não conta no TOTAL (injetado fora)
TOTAL_LINES = H + 6   # H radar + sep + 4 nome + tagline

def get_hud_top(): return _hud_top()
def get_hud_bot(): return _hud_bot()

# ══════════════════════════════════════════════════════════════════════════════
# KEY READER
# ══════════════════════════════════════════════════════════════════════════════
def _start_key_reader(stop_event):
    fd=sys.stdin.fileno()
    try: old=termios.tcgetattr(fd)
    except Exception: return
    def _reader():
        try:
            tty.setraw(fd)
            import select
            while not stop_event.is_set():
                r,_,_=select.select([sys.stdin],[],[],0.1)
                if r:
                    ch=sys.stdin.read(1)
                    if ch in ('\x03','\x18','\x04','q','Q'):
                        stop_event.set(); break
        except Exception: stop_event.set()
        finally:
            try: termios.tcsetattr(fd,termios.TCSADRAIN,old)
            except Exception: pass
    threading.Thread(target=_reader,daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE
# ══════════════════════════════════════════════════════════════════════════════
def _run():
    try:
        import ctypes; k=ctypes.windll.kernel32  # type: ignore
        k.SetConsoleMode(k.GetStdHandle(-11),7)
    except Exception: pass
    out=sys.stdout; stop=threading.Event()
    out.write('\033[?1049h\033[?25l\033[?1000l\033[?1002l\033[?1006l\033[2J\033[H')
    out.flush()
    ttl='M O O N S H I E L D   R A D A R'
    bdr=C_DIM+'─'*W+_R
    _start_key_reader(stop)
    for _ in range(3): add_ping()
    t=0
    try:
        while not stop.is_set():
            buf=['\033[H',
                 '\033[2K'+bdr,
                 '\033[2K'+C_NAME+_center(ttl,W)+_R,
                 '\033[2K'+bdr,
                 '\033[2K'+get_hud_top()]
            buf+=['\033[2K'+l for l in get_radar_lines()]
            buf.append('\033[2K'+get_hud_bot())
            buf+=['\033[2K'+l for l in get_signature_lines()]
            out.write('\n'.join(buf)); out.flush()
            t+=1
            if t%70==0: add_ping()
            time.sleep(0.05)
    except KeyboardInterrupt: pass
    finally:
        out.write('\033[?25h\033[?1049l'); out.flush()

if __name__=='__main__':
    _run()