"""
firewall/monitoramento/sincronizador.py  v5
──────────────────────────────────────────────────────────────────────
Proteção automática de IPs críticos — sem hardcode.

Ao iniciar detecta automaticamente:
  - IP do Django   → extraído da Moon_url
  - IP do sensor   → UDP trick (kernel resolve qual IP usa pra sair)
  - IP do gateway  → lido de `ip route show default`

Injeta no topo da chain antes de qualquer regra do usuário:
  insert rule inet moonshield ms_rules ip saddr <IP> accept
──────────────────────────────────────────────────────────────────────
"""

import hashlib
import os
import re
import socket
import subprocess
import threading
import time
import logging

from firewall.nucleo.conversor import gerar_script_nft, validar_iface_map
from nucleo.utilitarios import agora

logger = logging.getLogger(__name__)

VERSAO_SINCRONIZADOR = "5.0"
POLL_INTERVAL        = 30
PENDING_PATH         = "/firewall/api/pending-rules/"
CONFIRM_PATH         = "/firewall/api/confirm-rules/"
TMP_NFT_FILE         = "/tmp/ms_rules_sync.nft"

_sync_stats = {
    "rodando":           False,
    "ultimo_poll":       "—",
    "ultimo_apply":      "—",
    "aplicacoes":        0,
    "erros":             0,
    "regras_ativas":     0,
    "ultima_versao":     "—",
    "polls_sem_mudanca": 0,
    "ips_protegidos":    [],
}
_sync_lock = threading.Lock()
_hash_regras_aplicadas = None


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO AUTOMÁTICA DE IPs CRÍTICOS
# ══════════════════════════════════════════════════════════════════════════════

def _ip_do_django(moon_url):
    try:
        m = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', moon_url)
        return m.group(1) if m else None
    except Exception:
        return None


def _ip_do_sensor():
    """UDP trick — pergunta ao kernel qual IP usaria para sair à rede."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass
    return None


def _ip_do_gateway():
    """Lê o gateway padrão de `ip route show default`."""
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _coletar_ips_protegidos(moon_url):
    """Detecta todos os IPs críticos automaticamente — sem hardcode."""
    ips = []

    ip = _ip_do_django(moon_url)
    if ip:
        ips.append(ip)
        logger.info(f"[sync] IP Django: {ip}")
    else:
        logger.warning("[sync] Não foi possível extrair IP do Django")

    ip = _ip_do_sensor()
    if ip and ip not in ips:
        ips.append(ip)
        logger.info(f"[sync] IP Sensor: {ip}")
    else:
        logger.warning("[sync] Não foi possível detectar IP do sensor")

    ip = _ip_do_gateway()
    if ip and ip not in ips:
        ips.append(ip)
        logger.info(f"[sync] IP Gateway: {ip}")
    else:
        logger.warning("[sync] Não foi possível detectar gateway")

    return ips


# ══════════════════════════════════════════════════════════════════════════════
# SCRIPT COM PROTEÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _script_com_protecao(rules, iface_map, ips_protegidos):
    script = gerar_script_nft(rules, iface_map)

    if not ips_protegidos:
        return script

    linhas_prot = ["# ── IPs críticos sempre permitidos (auto-detectados) ──"]
    for ip in ips_protegidos:
        linhas_prot.append(
            f"insert rule inet moonshield ms_rules ip saddr {ip} accept"
        )
    linhas_prot.append("")

    linhas    = script.splitlines()
    resultado = []
    for linha in linhas:
        resultado.append(linha)
        if linha.strip().startswith("flush chain inet moonshield ms_rules"):
            resultado.append("")
            resultado.extend(linhas_prot)

    return "\n".join(resultado)


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def _hash_regras(rules):
    chave = sorted(
        f"{r.get('id')}|{r.get('action')}|{r.get('src')}|{r.get('dst')}|"
        f"{r.get('port')}|{r.get('priority')}|{r.get('enabled')}|"
        f"{r.get('iface')}|{r.get('proto')}|{r.get('dir')}"
        for r in rules
    )
    return hashlib.md5(str(chave).encode()).hexdigest()


def obter_stats():
    with _sync_lock:
        return dict(_sync_stats)


def esta_rodando():
    with _sync_lock:
        return _sync_stats["rodando"]


def iniciar_sincronizador(cfg, parar, session, session_lock):
    with _sync_lock:
        _sync_stats.update({
            "rodando": True, "ultimo_poll": "—", "ultimo_apply": "—",
            "aplicacoes": 0, "erros": 0, "regras_ativas": 0,
            "ultima_versao": "—", "polls_sem_mudanca": 0,
            "ips_protegidos": [],
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


# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def _loop_sincronizador(cfg, parar, session, session_lock):
    pending_url = cfg["Moon_url"].rstrip("/") + PENDING_PATH
    confirm_url = cfg["Moon_url"].rstrip("/") + CONFIRM_PATH
    headers     = {"X-MS-TOKEN": cfg.get("token", "")}

    ips_protegidos = _coletar_ips_protegidos(cfg.get("Moon_url", ""))
    with _sync_lock:
        _sync_stats["ips_protegidos"] = ips_protegidos

    if ips_protegidos:
        logger.info(f"[sync] IPs protegidos: {', '.join(ips_protegidos)}")
    else:
        logger.warning("[sync] Nenhum IP crítico detectado — proteção desativada")

    iface_map = cfg.get("iface_map", {"WAN": "eth0", "LAN": "eth1", "VPN": "tun0"})
    for aviso in validar_iface_map(iface_map):
        logger.warning(f"[sync] {aviso}")

    logger.info(f"[sync] v{VERSAO_SINCRONIZADOR} — poll a cada {POLL_INTERVAL}s | iface_map: {iface_map}")

    while not parar.is_set():
        try:
            _poll_e_aplicar(
                pending_url, confirm_url, headers,
                iface_map, session, session_lock,
                cfg, ips_protegidos,
            )
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


# ══════════════════════════════════════════════════════════════════════════════
# POLL E APLICAR
# ══════════════════════════════════════════════════════════════════════════════

def _poll_e_aplicar(pending_url, confirm_url, headers, iface_map,
                    session, session_lock, cfg, ips_protegidos):
    global _hash_regras_aplicadas

    with _sync_lock:
        _sync_stats["ultimo_poll"] = agora()

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

    rules       = data.get("rules", [])
    iface_final = {**data.get("iface_map", {}), **iface_map}  # local tem prioridade

    hash_atual = _hash_regras(rules)
    if hash_atual == _hash_regras_aplicadas:
        with _sync_lock:
            _sync_stats["polls_sem_mudanca"] += 1
        logger.debug("[sync] Sem mudança — skip")
        _confirmar(confirm_url, headers, [r["id"] for r in rules if "id" in r],
                   True, "sem mudanca", session, session_lock)
        return

    logger.info(
        f"[sync] {data.get('pendentes', 0)} pendente(s) — "
        f"{len(rules)} regras | protegendo: {', '.join(ips_protegidos) or '—'}"
    )

    ok, msg  = _aplicar_regras(rules, iface_final, ips_protegidos)
    rule_ids = [r["id"] for r in rules if "id" in r]
    _confirmar(confirm_url, headers, rule_ids, ok, msg, session, session_lock)

    with _sync_lock:
        if ok:
            _hash_regras_aplicadas       = hash_atual
            _sync_stats["aplicacoes"]   += 1
            _sync_stats["ultimo_apply"]  = agora()
            _sync_stats["regras_ativas"] = _contar_regras_ativas()
            _sync_stats["ultima_versao"] = agora()
        else:
            _sync_stats["erros"] += 1


def _aplicar_regras(rules, iface_map, ips_protegidos):
    script = _script_com_protecao(rules, iface_map, ips_protegidos)
    try:
        with open(TMP_NFT_FILE, "w", encoding="utf-8") as f:
            f.write(script)

        result = subprocess.run(
            ["nft", "-f", TMP_NFT_FILE],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            err = (result.stderr or result.stdout or "erro desconhecido").strip()
            logger.error(f"[sync] nft -f falhou: {err}\nScript:\n{script}")
            return False, f"nft error: {err[:200]}"

        prot = f" | protegidos: {', '.join(ips_protegidos)}" if ips_protegidos else ""
        logger.info(f"[sync] {len(rules)} regras aplicadas ✓{prot}")
        return True, f"{len(rules)} regras aplicadas"

    except subprocess.TimeoutExpired:
        return False, "Timeout ao aplicar regras"
    except FileNotFoundError:
        return False, "nft não encontrado"
    except Exception as e:
        return False, str(e)
    finally:
        try:
            os.remove(TMP_NFT_FILE)
        except Exception:
            pass


def _contar_regras_ativas():
    try:
        result = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", "ms_rules"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.count(" drop") + result.stdout.count(" accept")
    except Exception:
        return 0


def _confirmar(confirm_url, headers, rule_ids, success, msg, session, session_lock):
    try:
        with session_lock:
            resp = session.post(
                confirm_url,
                json={"rule_ids": rule_ids, "success": success, "msg": msg},
                headers=headers, timeout=10,
            )
        if not resp.ok:
            logger.warning(f"[sync] Falha ao confirmar: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"[sync] Erro ao confirmar: {e}")


def _renovar_token(cfg, session, session_lock):
    try:
        login_url = cfg["Moon_url"].rstrip("/") + "/auth/login/"
        with session_lock:
            r    = session.get(login_url, timeout=5)
            csrf = session.cookies.get("csrftoken", "")
            if not csrf:
                m    = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
                csrf = m.group(1) if m else ""
            session.post(
                login_url,
                data={
                    "username":            cfg.get("Moon_usuario", ""),
                    "password":            cfg.get("Moon_senha", ""),
                    "csrfmiddlewaretoken": csrf,
                },
                headers={"Referer": login_url},
                timeout=5, allow_redirects=True,
            )
    except Exception as e:
        logger.warning(f"[sync] Falha ao renovar token: {e}")