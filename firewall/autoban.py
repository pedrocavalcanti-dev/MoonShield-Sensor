"""
firewall/autoban.py
──────────────────────────────────────────────────────────────────────
Auto-ban emergencial: monitora eventos do journald e bane IPs
que atingirem o threshold localmente via nft, sem esperar o Django.
Em seguida sobe o bloqueio para o Django via /firewall/api/autoban/.
──────────────────────────────────────────────────────────────────────
"""

import subprocess
import threading
import time
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

AUTOBAN_PATH = "/firewall/api/autoban/"

# Thresholds padrão — sobrescritos pelo config.json se tiver campo "autoban"
DEFAULTS = {
    "habilitado":      True,
    "janela_seg":      30,    # janela de tempo para contar hits
    "threshold":       15,    # hits dentro da janela para disparar ban
    "expire_seg":      3600,  # duração do ban emergencial (0 = permanente)
    "portas_sensiveis": [22, 23, 3389, 5900],  # peso dobrado nessas portas
}

_ban_stats = {
    "total_bans":  0,
    "ultimo_ban":  "—",
    "ultimo_ip":   "—",
}
_ban_lock     = threading.Lock()
_bans_ativos  = set()          # IPs já banados nesta sessão
_hit_counter  = defaultdict(list)  # ip → [timestamps]
_counter_lock = threading.Lock()


def obter_stats() -> dict:
    with _ban_lock:
        return dict(_ban_stats)


def registrar_evento(ev: dict, cfg: dict, session, session_lock):
    """
    Chamado pelo monitoramento.py a cada evento recebido.
    Verifica se o IP atingiu o threshold e bane se necessário.
    """
    ab_cfg    = {**DEFAULTS, **cfg.get("autoban", {})}
    if not ab_cfg["habilitado"]:
        return

    src_ip = ev.get("src_ip")
    if not src_ip or src_ip in _bans_ativos:
        return

    # Ignora IPs privados
    if _ip_privado(src_ip):
        return

    agora = time.time()
    janela = ab_cfg["janela_seg"]
    peso   = 2 if ev.get("dst_port") in ab_cfg["portas_sensiveis"] else 1

    with _counter_lock:
        # Remove hits fora da janela
        _hit_counter[src_ip] = [t for t in _hit_counter[src_ip] if agora - t < janela]
        # Adiciona hit atual (peso = quantos "hits" conta)
        _hit_counter[src_ip].extend([agora] * peso)
        total_hits = len(_hit_counter[src_ip])

    if total_hits >= ab_cfg["threshold"]:
        _executar_ban(src_ip, total_hits, janela, ev, ab_cfg, cfg, session, session_lock)


def _executar_ban(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock):
    """Ban local imediato + notificação ao Django."""
    with _ban_lock:
        if ip in _bans_ativos:
            return
        _bans_ativos.add(ip)

    logger.warning(f"[autoban] Banindo {ip} — {hits} hits em {janela}s")

    # Ban local via nft na chain ms_emergency (sem esperar Django)
    ok_nft, msg_nft = _ban_nft(ip, ab_cfg)
    if ok_nft:
        logger.info(f"[autoban] {ip} banido via nft ✓")
    else:
        logger.error(f"[autoban] Falha ao banar {ip} via nft: {msg_nft}")

    # Sobe para o Django em background
    threading.Thread(
        target=_notificar_django,
        args=(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock),
        daemon=True,
    ).start()

    with _ban_lock:
        _ban_stats["total_bans"] += 1
        _ban_stats["ultimo_ban"] = datetime.now().strftime("%H:%M:%S")
        _ban_stats["ultimo_ip"]  = ip

    # Agenda remoção automática se expires > 0
    if ab_cfg["expire_seg"] > 0:
        threading.Thread(
            target=_remover_ban_apos,
            args=(ip, ab_cfg["expire_seg"]),
            daemon=True,
        ).start()


def _ban_nft(ip: str, ab_cfg: dict) -> tuple[bool, str]:
    """Adiciona regra DROP na chain ms_emergency."""
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
    """Remove regra de autoban da chain ms_emergency."""
    try:
        # Lista as regras, acha o handle da regra com esse IP e deleta
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
    """Remove o ban após o tempo de expiração."""
    time.sleep(segundos)
    _remover_ban_nft(ip)
    with _ban_lock:
        _bans_ativos.discard(ip)
    with _counter_lock:
        _hit_counter.pop(ip, None)
    logger.info(f"[autoban] Ban de {ip} expirado após {segundos}s")


def _notificar_django(ip, hits, janela, ev, ab_cfg, cfg, session, session_lock):
    """POST /firewall/api/autoban/ para registrar no painel."""
    url = cfg["Moon_url"].rstrip("/") + AUTOBAN_PATH
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
    """Retorna True para IPs RFC1918 e loopback."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False