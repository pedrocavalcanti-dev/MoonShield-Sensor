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
PING_LIFE  = 32
PING_CHARS = ['+','x','*','●','◆']
NOISE_LIFE = 5
WAVE_MAX   = 3
WAVE_LIFE  = 8

# ══════════════════════════════════════════════════════════════════════════════
# PALETA
# ══════════════════════════════════════════════════════════════════════════════
_R = '\033[0m'
def _fg(n): return f'\033[38;5;{n}m'

SWEEP_PAL = [_fg(82),_fg(46),_fg(40),_fg(34),_fg(28),_fg(22),_fg(237),_fg(235)]
PING_PAL  = [_fg(226),_fg(220),_fg(214),_fg(208),_fg(166),_fg(130),_fg(237)]
WAVE_PAL  = [_fg(51),_fg(45),_fg(39),_fg(33),_fg(27),_fg(237)]

C_RING_O=_fg(22); C_RING_M=_fg(28); C_RING_I=_fg(34)
C_CROSS =_fg(22); C_CENTER=_fg(46);  C_OUT=_fg(232)
C_NOISE =_fg(234);C_DIM=_fg(238);   C_NAME=_fg(40); C_TAG=_fg(28)

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
        if not _ic(_r,_c): _CELLS[(_r,_c)]='out'
        elif _r==CY and _c==CX: _CELLS[(_r,_c)]='ctr'
        else:
            d=_dist(_r,_c)/RADIUS
            if abs(d-.33)<.04 or abs(d-.66)<.03 or abs(d-.99)<.03:
                _CELLS[(_r,_c)]='ring'
            elif _r==CY or _c==CX:
                _CELLS[(_r,_c)]='cross'
            else:
                _CELLS[(_r,_c)]='fill'

_FILL=[(r,c) for (r,c),k in _CELLS.items() if k=='fill']

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
    """Chamado pelo monitoramento em alertas reais."""
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
# RENDER
# ══════════════════════════════════════════════════════════════════════════════
def get_radar_lines():
    _tick()
    sweep=_st["angle"]
    pmap={(p["r"],p["c"]):p for p in _st["pings"]}
    nset={(n["r"],n["c"]) for n in _st["noise"]}

    wave_cells={}
    for wv in _st["waves"]:
        wr=(wv["age"]+1)*1.6
        wi=wv["age"]/WAVE_LIFE
        for r in range(H):
            for c in range(W):
                if _CELLS[(r,c)] in ('fill','ring','cross'):
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
            if k=='out':   w(C_OUT,' ');    continue
            if k=='ctr':   w(C_CENTER,'+'); continue
            if (r,c) in pmap:
                p=pmap[(r,c)]
                pi=min(p["age"]*len(PING_PAL)//PING_LIFE,len(PING_PAL)-1)
                ch=p["ch"] if p["age"]%3!=1 else '·'
                w(PING_PAL[pi],ch); continue
            if (r,c) in wave_cells:
                wi=wave_cells[(r,c)]
                wpi=min(int((1-wi)*len(WAVE_PAL)),len(WAVE_PAL)-1)
                w(WAVE_PAL[wpi],'·'); continue
            diff=(sweep-_ang(r,c))%360
            if diff<=TRAIL_DEG:
                lvl=int(diff/TRAIL_DEG*(TRAIL_LVL-1))
                if k=='ring':    ch='·'
                elif k=='cross': ch='─' if r==CY else '│'
                else:            ch=['█','▓','▓','▒','░','░','·',' '][lvl]
                w(SWEEP_PAL[lvl],ch); continue
            if (r,c) in nset: w(C_NOISE,'·'); continue
            if k=='ring':    w(_rcol(r,c),'·')
            elif k=='cross': w(C_CROSS,'─' if r==CY else '│')
            else:            w(C_OUT,' ')
        lines.append(seg+_R)
    return lines

def get_signature_lines():
    nl='── P . C a v a l c a n t i ──'
    tl='network sensor  //  MoonShield'
    sep=C_DIM+'·'*W+_R
    return [
        sep,
        C_NAME+' '*((W-len(nl))//2)+nl+_R,
        C_TAG +' '*((W-len(tl))//2)+tl+_R,
    ]

TOTAL_LINES = H + 3

# ══════════════════════════════════════════════════════════════════════════════
# LEITOR DE TECLA — thread separada, não bloqueia o loop principal
# Retorna 'q' para Ctrl+C (^C = \x03) ou Ctrl+X (^X = \x18)
# ══════════════════════════════════════════════════════════════════════════════
def _start_key_reader(stop_event):
    """
    Lê stdin em modo raw numa thread separada.
    Seta stop_event se receber Ctrl+C (\x03) ou Ctrl+X (\x18).
    """
    import os
    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except Exception:
        return   # não é um tty (ex: pipe), ignora

    def _reader():
        try:
            tty.setraw(fd)
            while not stop_event.is_set():
                # select para não bloquear para sempre
                import select
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

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    return t

# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE
# ══════════════════════════════════════════════════════════════════════════════
def _run():
    try:
        import ctypes; k=ctypes.windll.kernel32  # type: ignore
        k.SetConsoleMode(k.GetStdHandle(-11),7)
    except Exception: pass

    out=sys.stdout
    stop=threading.Event()

    out.write('\033[?1049h\033[?25l\033[?1000l\033[?1002l\033[?1006l\033[2J\033[H')
    out.flush()

    ttl='M O O N S H I E L D   R A D A R'
    pad=' '*((W-len(ttl))//2)
    bdr=C_DIM+'─'*W+_R

    _start_key_reader(stop)
    for _ in range(3): add_ping()
    t=0
    try:
        while not stop.is_set():
            buf=['\033[H',
                 '\033[2K'+bdr,
                 '\033[2K'+C_NAME+pad+ttl+_R,
                 '\033[2K'+bdr]
            buf+=['\033[2K'+l for l in get_radar_lines()]
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