"""
firewall/sincronizador.py
──────────────────────────────────────────────────────────────────────
Sincroniza regras do Django para nftables via poll.
Poll em /firewall/api/pending-rules/ a cada 30s.
Quando há pendentes: gera script nft → aplica → confirma no Django.

O iface_map é relido do cfg a cada poll — o monitoramento.py já
o atualiza automaticamente via _detectar_interfaces(cfg), então
o analista nunca precisa editar o config manualmente.
──────────────────────────────────────────────────────────────────────
"""

import os
import subprocess
import threading
import time
import logging

from firewall.conversor import gerar_script_nft, validar_iface_map

logger = logging.getLogger(__name__)

POLL_INTERVAL = 30
PENDING_PATH  = "/firewall/api/pending-rules/"
CONFIRM_PATH  = "/firewall/api/confirm-rules/"
TMP_NFT_FILE  = "/tmp/ms_rules_sync.nft"

_sync_stats = {
    "rodando":      False,
    "ultimo_poll":  "—",
    "ultimo_apply": "—",
    "aplicacoes":   0,
    "erros":        0,
}
_sync_lock = threading.Lock()


def _agora():
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")


def obter_stats() -> dict:
    with _sync_lock:
        return dict(_sync_stats)


def esta_rodando() -> bool:
    with _sync_lock:
        return _sync_stats["rodando"]


def iniciar_sincronizador(cfg: dict, parar: threading.Event,
                          session, session_lock) -> threading.Thread:
    with _sync_lock:
        _sync_stats.update({
            "rodando": True, "ultimo_poll": "—",
            "ultimo_apply": "—", "aplicacoes": 0, "erros": 0,
        })
    t = threading.Thread(
        target=_loop_sincronizador,
        args=(cfg, parar, session, session_lock),
        daemon=True,
    )
    t.start()
    return t


def parar_sincronizador():
    with _sync_lock:
        _sync_stats["rodando"] = False


def _loop_sincronizador(cfg: dict, parar: threading.Event,
                        session, session_lock):
    pending_url = cfg["Moon_url"].rstrip("/") + PENDING_PATH
    confirm_url = cfg["Moon_url"].rstrip("/") + CONFIRM_PATH
    token       = cfg.get("token", "")
    headers     = {"X-MS-TOKEN": token}

    # iface_map é lido aqui só para o log inicial — será relido a cada poll
    # pois o monitoramento.py pode atualizá-lo via salvar_config após o
    # heartbeat inicial (detecção automática de interfaces).
    iface_map_inicial = cfg.get("iface_map", {"WAN": "eth0", "LAN": "eth1", "VPN": "tun0"})
    avisos = validar_iface_map(iface_map_inicial)
    for aviso in avisos:
        logger.warning(f"[sync] {aviso}")

    logger.info(f"[sync] Iniciado — poll a cada {POLL_INTERVAL}s | iface_map: {iface_map_inicial}")

    while not parar.is_set():
        try:
            # Relê iface_map do cfg a cada iteração — reflete o que
            # _detectar_interfaces(cfg) salvou no heartbeat do monitoramento
            iface_map = cfg.get("iface_map", {"WAN": "eth0", "LAN": "eth1", "VPN": "tun0"})

            _poll_e_aplicar(pending_url, confirm_url, headers, iface_map,
                            session, session_lock, cfg)
        except Exception as e:
            logger.error(f"[sync] Erro no loop: {e}")
            with _sync_lock:
                _sync_stats["erros"] += 1

        for _ in range(POLL_INTERVAL * 10):
            if parar.is_set():
                break
            time.sleep(0.1)

    with _sync_lock:
        _sync_stats["rodando"] = False
    logger.info("[sync] Encerrado")


def _poll_e_aplicar(pending_url, confirm_url, headers, iface_map,
                    session, session_lock, cfg):
    with _sync_lock:
        _sync_stats["ultimo_poll"] = _agora()

    try:
        with session_lock:
            resp = session.get(pending_url, headers=headers, timeout=10)
    except Exception as e:
        logger.warning(f"[sync] Falha no poll: {e}")
        return

    if resp.status_code == 403:
        logger.warning("[sync] Token inválido — tentando renovar")
        _renovar_token(cfg, session, session_lock)
        return

    if not resp.ok:
        logger.warning(f"[sync] Poll HTTP {resp.status_code}")
        return

    data = resp.json()
    if not data.get("ok") or not data.get("tem_pendentes"):
        return

    rules     = data.get("rules", [])
    im_remoto = data.get("iface_map", {})
    iface_final = {**im_remoto, **iface_map}  # local tem prioridade

    logger.info(f"[sync] {data.get('pendentes', 0)} pendente(s) — aplicando {len(rules)} regras")

    ok, msg = _aplicar_regras(rules, iface_final)
    rule_ids = [r["id"] for r in rules if "id" in r]
    _confirmar(confirm_url, headers, rule_ids, ok, msg, session, session_lock)

    with _sync_lock:
        if ok:
            _sync_stats["aplicacoes"] += 1
            _sync_stats["ultimo_apply"] = _agora()
        else:
            _sync_stats["erros"] += 1


def _aplicar_regras(rules: list, iface_map: dict) -> tuple[bool, str]:
    if not rules:
        return True, "Sem regras"

    script = gerar_script_nft(rules, iface_map)
    try:
        with open(TMP_NFT_FILE, "w", encoding="utf-8") as f:
            f.write(script)

        result = subprocess.run(
            ["nft", "-f", TMP_NFT_FILE],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "erro desconhecido").strip()
            logger.error(f"[sync] nft -f falhou: {err}")
            return False, f"nft error: {err[:200]}"

        logger.info(f"[sync] {len(rules)} regras aplicadas ✓")
        return True, f"{len(rules)} regras aplicadas"

    except subprocess.TimeoutExpired:
        return False, "Timeout ao aplicar regras"
    except FileNotFoundError:
        return False, "nft não encontrado"
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(TMP_NFT_FILE):
            try:
                os.remove(TMP_NFT_FILE)
            except Exception:
                pass


def _confirmar(confirm_url, headers, rule_ids, success, msg,
               session, session_lock):
    try:
        payload = {"rule_ids": rule_ids, "success": success, "msg": msg}
        with session_lock:
            resp = session.post(confirm_url, json=payload, headers=headers, timeout=10)
        if resp.ok:
            logger.debug(f"[sync] Confirmação: {success} | {msg}")
        else:
            logger.warning(f"[sync] Falha ao confirmar: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[sync] Erro ao confirmar: {e}")


def _renovar_token(cfg, session, session_lock):
    try:
        import re
        base      = cfg["Moon_url"].rstrip("/")
        login_url = base + "/auth/login/"
        with session_lock:
            r    = session.get(login_url, timeout=5)
            csrf = session.cookies.get("csrftoken", "")
            if not csrf:
                m    = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
                csrf = m.group(1) if m else ""
            session.post(
                login_url,
                data={"username": cfg.get("Moon_usuario", ""),
                      "password": cfg.get("Moon_senha", ""),
                      "csrfmiddlewaretoken": csrf},
                headers={"Referer": login_url},
                timeout=5, allow_redirects=True,
            )
    except Exception as e:
        logger.warning(f"[sync] Falha ao renovar token: {e}")