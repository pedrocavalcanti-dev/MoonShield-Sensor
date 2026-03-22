"""
firewall/monitoramento/autoban.py
──────────────────────────────────────────────────────────────────────
Auto-ban emergencial: monitora eventos e bane IPs que atingirem
o threshold localmente via nft, sem esperar o Django.
Em seguida sobe o bloqueio para o Django via /firewall/api/autoban/.

v2: stats ricos (bans_sessao, ultimo_motivo, ips_ativos),
    listar_bans_ativos(), VERSAO_AUTOBAN.
──────────────────────────────────────────────────────────────────────
"""

import subprocess
import threading
import time
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_AUTOBAN = "2.0"
AUTOBAN_PATH   = "/firewall/api/autoban/"

DEFAULTS = {
    "habilitado":       True,
    "janela_seg":       30,
    "threshold":        15,
    "expire_seg":       3600,
    "portas_sensiveis": [22, 23, 3389, 5900],
}

# ══════════════════════════════════════════════════════════════════════════════
# ESTADO
# ══════════════════════════════════════════════════════════════════════════════

_ban_stats = {
    "total_bans":    0,
    "bans_sessao":   0,
    "ultimo_ban":    "—",
    "ultimo_ip":     "—",
    "ultimo_motivo": "—",
}
_ban_lock    = threading.Lock()
_bans_ativos = set()               # IPs já banados nesta sessão
_hit_counter = defaultdict(list)   # ip → [timestamps]
_counter_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def obter_stats() -> dict:
    """v2: inclui ips_ativos calculado em tempo real."""
    with _ban_lock:
        return {**_ban_stats, "ips_ativos": len(_bans_ativos)}


def listar_bans_ativos() -> list:
    """Retorna lista de IPs atualmente banados nesta sessão."""
    with _ban_lock:
        return list(_bans_ativos)


def registrar_evento(ev: dict, cfg: dict, session, session_lock):
    """
    Chamado pelo monitoramento.py a cada evento recebido.
    Verifica threshold e bane se necessário.
    """
    ab_cfg = {**DEFAULTS, **cfg.get("autoban", {})}
    if not ab_cfg["habilitado"]:
        return

    src_ip = ev.get("src_ip")
    if not src_ip or src_ip in _bans_ativos:
        return

    if _ip_privado(src_ip):
        return

    agora = time.time()
    janela = ab_cfg["janela_seg"]
    peso   = 2 if ev.get("dst_port") in ab_cfg["portas_sensiveis"] else 1

    with _counter_lock:
        _hit_counter[src_ip] = [t for t in _hit_counter[src_ip] if agora - t < janela]
        _hit_counter[src_ip].extend([agora] * peso)
        total_hits = len(_hit_counter[src_ip])

    if total_hits >= ab_cfg["threshold"]:
        _executar_ban(src_ip, total_hits, janela, ev, ab_cfg, cfg, session, session_lock)

# ══════════════════════════════════════════════════════════════════════════════
# BAN
# ══════════════════════════════════════════════════════════════════════════════

def _executar_ban(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock):
    with _ban_lock:
        if ip in _bans_ativos:
            return
        _bans_ativos.add(ip)

    motivo = _detectar_motivo(ev)
    logger.warning(f"[autoban] Banindo {ip} — {hits} hits em {janela}s | motivo: {motivo}")

    ok_nft, msg_nft = _ban_nft(ip, ab_cfg)
    if ok_nft:
        logger.info(f"[autoban] {ip} banido via nft ✓")
    else:
        logger.error(f"[autoban] Falha ao banar {ip} via nft: {msg_nft}")

    threading.Thread(
        target=_notificar_django,
        args=(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock),
        daemon=True,
    ).start()

    with _ban_lock:
        _ban_stats["total_bans"]    += 1
        _ban_stats["bans_sessao"]   += 1
        _ban_stats["ultimo_ban"]     = datetime.now().strftime("%H:%M:%S")
        _ban_stats["ultimo_ip"]      = ip
        _ban_stats["ultimo_motivo"]  = motivo   # v2

    if ab_cfg["expire_seg"] > 0:
        threading.Thread(
            target=_remover_ban_apos,
            args=(ip, ab_cfg["expire_seg"]),
            daemon=True,
        ).start()


def _ban_nft(ip: str, ab_cfg: dict) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["nft", "add", "rule", "inet", "moonshield", "ms_emergency",
             "ip", "saddr", ip, "drop"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, "ok"
    except FileNotFoundError:
        return False, "nft não encontrado"
    except Exception as e:
        return False, str(e)


def _remover_ban_nft(ip: str):
    try:
        result = subprocess.run(
            ["nft", "-a", "list", "chain", "inet", "moonshield", "ms_emergency"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return
        for line in result.stdout.splitlines():
            if ip in line and "# handle" in line:
                handle = line.split("# handle")[-1].strip()
                subprocess.run(
                    ["nft", "delete", "rule", "inet", "moonshield", "ms_emergency",
                     "handle", handle],
                    capture_output=True, timeout=5,
                )
                break
    except Exception as e:
        logger.warning(f"[autoban] Erro ao remover ban de {ip}: {e}")


def _remover_ban_apos(ip: str, segundos: int):
    time.sleep(segundos)
    _remover_ban_nft(ip)
    with _ban_lock:
        _bans_ativos.discard(ip)
    with _counter_lock:
        _hit_counter.pop(ip, None)
    logger.info(f"[autoban] Ban de {ip} expirado após {segundos}s")

# ══════════════════════════════════════════════════════════════════════════════
# DJANGO
# ══════════════════════════════════════════════════════════════════════════════

def _notificar_django(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock):
    url   = cfg["Moon_url"].rstrip("/") + AUTOBAN_PATH
    token = cfg.get("token", "")
    payload = {
        "ip":     ip,
        "hits":   hits,
        "janela": janela,
        "motivo": _detectar_motivo(ev),
        "porta":  ev.get("dst_port"),
        "proto":  ev.get("proto"),
        "iface":  ev.get("iface_entrada") or ev.get("iface", ""),
        "sensor": cfg.get("sensor_nome", ""),
        "source": "Auto",
    }
    for tentativa in range(3):
        try:
            with session_lock:
                resp = session.post(
                    url, json=payload,
                    headers={"X-MS-TOKEN": token},
                    timeout=8,
                )
            if resp.ok:
                logger.info(f"[autoban] Django notificado: {ip}")
                return
            logger.warning(f"[autoban] Django retornou {resp.status_code}")
        except Exception as e:
            logger.warning(f"[autoban] Tentativa {tentativa+1} falhou: {e}")
        time.sleep(2 ** tentativa)

# ══════════════════════════════════════════════════════════════════════════════
# UTILITÁRIOS
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_motivo(ev: dict) -> str:
    porta = ev.get("dst_port")
    if porta == 22:   return "brute_force_ssh"
    if porta == 23:   return "tentativa_telnet"
    if porta == 3389: return "brute_force_rdp"
    if porta == 5900: return "brute_force_vnc"
    flags = (ev.get("flags_tcp") or "").upper()
    if "SYN" in flags and "ACK" not in flags:
        return "port_scan_syn"
    return "threshold_excedido"


def _ip_privado(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False