#!/usr/bin/env python3
"""
nucleo/radar.py - Motor do radar ASCII. Importado por monitoramento.py.
Standalone: python3 -m nucleo.radar
"""
import math, time, random, sys

W=55; H=27; CX=W//2; CY=H//2; AY=0.52; RADIUS=min(CX,CY-1)
SWEEP_DEG=4.0; TRAIL_DEG=55; TRAIL_LVL=7
PING_LIFE=28; PING_CHARS=['+','x','*','●','◆']
NOISE_D=0.012; NOISE_LIFE=6

_R='\033[0m'
def _fg(n): return f'\033[38;5;{n}m'
def _b():   return '\033[1m'

SWEEP_PAL=[_b()+_fg(46),_fg(46),_fg(40),_fg(34),_fg(28),_fg(22),_fg(236)]
PING_PAL=[_b()+_fg(226),_b()+_fg(220),_fg(214),_fg(208),_fg(166),_fg(130),_fg(236)]
C_RING_O=_fg(22); C_RING_M=_fg(28); C_RING_I=_fg(34)
C_CROSS=_fg(22);  C_CENTER=_b()+_fg(46); C_OUT=_fg(232)
C_NOISE=_fg(234); C_DIM=_fg(238); C_NAME=_b()+_fg(40); C_TAG=_fg(28)

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
            if abs(d-.33)<.04 or abs(d-.66)<.03 or abs(d-.99)<.03: _CELLS[(_r,_c)]='ring'
            elif _r==CY or _c==CX: _CELLS[(_r,_c)]='cross'
            else: _CELLS[(_r,_c)]='fill'

_FILL=[(r,c) for (r,c),k in _CELLS.items() if k=='fill']
_st={"tick":0,"angle":0.0,"pings":[],"noise":[]}

def _tick():
    s=_st; s["tick"]+=1; s["angle"]=(s["angle"]+SWEEP_DEG)%360
    s["pings"]=[p for p in s["pings"] if p["age"]<PING_LIFE]
    for p in s["pings"]: p["age"]+=1
    s["noise"]=[n for n in s["noise"] if n["age"]<NOISE_LIFE]
    for n in s["noise"]: n["age"]+=1
    for r,c in random.sample(_FILL,min(8,len(_FILL))):
        if random.random()<NOISE_D: s["noise"].append({"r":r,"c":c,"age":0})

def add_ping(r=None,c=None):
    """Adiciona ping. Chamado pelo monitoramento em alertas reais."""
    ang=_st["angle"]
    if r is None:
        for _ in range(60):
            cr,cc=random.choice(_FILL)
            if (ang-_ang(cr,cc))%360<12: r,c=cr,cc; break
        else: r,c=random.choice(_FILL)
    _st["pings"].append({"r":r,"c":c,"age":0,"ch":random.choice(PING_CHARS)})

def get_radar_lines():
    _tick()
    sweep=_st["angle"]
    pmap={(p["r"],p["c"]):p for p in _st["pings"]}
    nset={(n["r"],n["c"]) for n in _st["noise"]}
    lines=[]
    for r in range(H):
        seg=""; pc=None
        def w(col,ch,_seg=None,_pc=None):
            nonlocal seg,pc
            if col!=pc: seg+=_R+col; pc=col
            seg+=ch
        for c in range(W):
            k=_CELLS[(r,c)]
            if k=='out':  w(C_OUT,' ');   continue
            if k=='ctr':  w(C_CENTER,'+'); continue
            if (r,c) in pmap:
                p=pmap[(r,c)]; i=min(p["age"]*len(PING_PAL)//PING_LIFE,len(PING_PAL)-1)
                w(PING_PAL[i],p["ch"]); continue
            diff=(sweep-_ang(r,c))%360
            if diff<=TRAIL_DEG:
                lvl=int(diff/TRAIL_DEG*(TRAIL_LVL-1))
                ch=('·' if k=='ring' else ('─' if r==CY else '│') if k=='cross' else ['█','▓','▒','░','·','·',' '][lvl])
                w(SWEEP_PAL[lvl],ch); continue
            if (r,c) in nset: w(C_NOISE,'·'); continue
            if k=='ring':  w(_rcol(r,c),'·')
            elif k=='cross': w(C_CROSS,'─' if r==CY else '│')
            else: w(C_OUT,' ')
        lines.append(seg+_R)
    return lines

def get_signature_lines():
    sep=C_DIM+'·'*W+_R
    nl='── P . C a v a l c a n t i ──'
    tl='network sensor  //  MoonShield'
    return [sep, C_NAME+' '*((W-len(nl))//2)+nl+_R, C_TAG+' '*((W-len(tl))//2)+tl+_R, '']

TOTAL_LINES = H + 4

def _run():
    try:
        import ctypes; k=ctypes.windll.kernel32; k.SetConsoleMode(k.GetStdHandle(-11),7)
    except Exception: pass
    out=sys.stdout
    ttl='M O O N S H I E L D   R A D A R'
    pad=' '*((W-len(ttl))//2); bdr='─'*W
    out.write('\033[?1049h\033[?25l\033[2J\033[H'); out.flush()
    for _ in range(3): add_ping()
    t=0
    try:
        while True:
            buf=['\033[H','\033[2K'+C_DIM+pad+bdr+_R,'\033[2K'+C_NAME+pad+ttl+_R,'\033[2K'+C_DIM+pad+bdr+_R]
            buf+=['\033[2K'+l for l in get_radar_lines()]
            buf+=['\033[2K'+l for l in get_signature_lines()]
            buf.append('\033[2K'+C_DIM+' '*((W-16)//2)+'Ctrl+C para sair'+_R)
            out.write('\n'.join(buf)); out.flush()
            t+=1
            if t%60==0: add_ping()
            time.sleep(0.05)
    except KeyboardInterrupt: pass
    finally: out.write('\033[?25h\033[?1049l'); out.flush()

if __name__=='__main__':
    _run()