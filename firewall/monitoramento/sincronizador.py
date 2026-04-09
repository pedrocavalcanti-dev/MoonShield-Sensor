"""
firewall/monitoramento/sincronizador.py  v6
──────────────────────────────────────────────────────────────────────
Correções v6:
  - _aplicar_so_protecoes() usava insert sem flush — acumulava regras.
    Agora só injeta proteções se a chain estiver vazia ou sem elas,
    sem fazer flush (não apaga regras do usuário).
  - iface_map lido do config.json do sensor (via cfg["iface_map"]).
    Fallback para detecção automática do sistema.
  - Hash de regras inclui iface_map para forçar reaplicação quando
    o mapa muda.
  - Loop sem pendentes não faz mais flush — só verifica se as
    proteções ainda estão na chain e injeta se sumiram.
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

VERSAO_SINCRONIZADOR = "6.0"
POLL_INTERVAL        = 3
PENDING_PATH         = "/firewall/api/pending-rules/"
CONFIRM_PATH         = "/firewall/api/confirm-rules/"
TMP_NFT_FILE         = "/tmp/ms_rules_sync.nft"

_sync_stats = {
    "rodando":           False,
    "ultimo_poll":       "—",
    "ultimo_apply":      "—",
    "aplicacoes":        0,
    "erros":             0,
    "sem_mudanca":       0,
    "polls":             0,
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

def _ip_do_django(moon_url: str) -> str | None:
    try:
        m = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', moon_url)
        return m.group(1) if m else None
    except Exception:
        return None


def _ip_do_sensor() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip if ip and not ip.startswith('127.') else None
    except Exception:
        return None


def _ip_do_gateway() -> str | None:
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _coletar_ips_protegidos(moon_url: str) -> list[str]:
    ips = []
    for fn, label in [
        (_ip_do_django(moon_url), "Django"),
        (_ip_do_sensor(),         "Sensor"),
        (_ip_do_gateway(),        "Gateway"),
    ]:
        if fn and fn not in ips:
            ips.append(fn)
            logger.info(f"[sync] IP {label}: {fn}")
        else:
            logger.debug(f"[sync] IP {label}: não detectado ou duplicado")
    return ips


# ══════════════════════════════════════════════════════════════════════════════
# SCRIPT COM PROTEÇÃO
# Gera o script nft completo com as regras do usuário + proteções no topo.
# ══════════════════════════════════════════════════════════════════════════════

def _script_com_protecao(rules: list, iface_map: dict, ips_protegidos: list) -> str:
    script = gerar_script_nft(rules, iface_map)

    if not ips_protegidos:
        return script

    linhas_prot = ["# IPs criticos sempre permitidos (auto-detectados)"]
    for ip in ips_protegidos:
        # insert coloca no topo da chain, antes das regras do usuario
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
# PROTEÇÕES SEM FLUSH
# Injeta IPs criticos na chain SEM fazer flush — nao apaga regras existentes.
# Usado quando nao ha pendentes mas precisamos garantir os IPs criticos.
# ══════════════════════════════════════════════════════════════════════════════

def _garantir_protecoes(ips_protegidos: list):
    """
    Verifica se os IPs criticos estao na chain.
    Se faltarem, injeta SEM flush (nao apaga regras do usuario).
    """
    if not ips_protegidos:
        return

    try:
        result = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", "ms_rules"],
            capture_output=True, text=True, timeout=5,
        )
        chain = result.stdout
    except Exception:
        return

    for ip in ips_protegidos:
        if f"ip saddr {ip} accept" not in chain:
            subprocess.run(
                ["nft", "insert", "rule", "inet", "moonshield", "ms_rules",
                 "ip", "saddr", ip, "accept"],
                capture_output=True, timeout=5,
            )
            logger.info(f"[sync] Proteção reinjetada (sem flush): {ip}")


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def _hash_regras(rules: list) -> str:
    chave = sorted(
        f"{r.get('id')}|{r.get('action')}|{r.get('src')}|{r.get('dst')}|"
        f"{r.get('port')}|{r.get('priority')}|{r.get('enabled')}|"
        f"{r.get('iface')}|{r.get('proto')}|{r.get('dir')}"
        for r in rules
    )
    return hashlib.md5(str(chave).encode()).hexdigest()


def obter_stats() -> dict:
    with _sync_lock:
        s = dict(_sync_stats)
    # Aliases para compatibilidade com o dashboard
    s["sem_mudanca"] = s.get("polls_sem_mudanca", 0)
    return s


def esta_rodando() -> bool:
    with _sync_lock:
        return _sync_stats["rodando"]


def iniciar_sincronizador(cfg, parar, session, session_lock):
    with _sync_lock:
        _sync_stats.update({
            "rodando": True, "ultimo_poll": "—", "ultimo_apply": "—",
            "aplicacoes": 0, "erros": 0, "sem_mudanca": 0, "polls": 0,
            "regras_ativas": 0, "ultima_versao": "—",
            "polls_sem_mudanca": 0, "ips_protegidos": [],
        })
    t = threading.Thread(
        target=_loop_sincronizador,
        args=(cfg, parar, session, session_lock),
        name="ms-sincronizador",
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

    # IPs criticos detectados uma vez ao iniciar
    ips_protegidos = _coletar_ips_protegidos(cfg.get("Moon_url", ""))
    with _sync_lock:
        _sync_stats["ips_protegidos"] = ips_protegidos

    # iface_map: usa o do config.json do sensor (ja mapeado corretamente)
    # Fallback para eth0/eth1 apenas se nao houver config
    iface_map = cfg.get("iface_map") or {"WAN": "eth0", "LAN": "eth1", "VPN": "tun0"}

    for aviso in validar_iface_map(iface_map):
        logger.warning(f"[sync] {aviso}")

    logger.info(
        f"[sync] v{VERSAO_SINCRONIZADOR} iniciado | "
        f"poll={POLL_INTERVAL}s | iface_map={iface_map} | "
        f"ips_protegidos={ips_protegidos}"
    )

    # Garante proteções ao iniciar sem fazer flush
    _garantir_protecoes(ips_protegidos)

    while not parar.is_set():
        try:
            _poll_e_aplicar(
                pending_url, confirm_url, headers,
                iface_map, session, session_lock,
                cfg, ips_protegidos,
            )
        except Exception as e:
            logger.error(f"[sync] Erro no loop: {e}", exc_info=True)
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
        _sync_stats["polls"]      += 1

    try:
        with session_lock:
            resp = session.get(pending_url, headers=headers, timeout=10)
    except Exception as e:
        logger.warning(f"[sync] Falha no poll: {e}")
        with _sync_lock:
            _sync_stats["erros"] += 1
        return

    if resp.status_code == 403:
        logger.warning("[sync] Token inválido — tentando renovar")
        _renovar_token(cfg, session, session_lock)
        return

    if not resp.ok:
        logger.warning(f"[sync] Poll HTTP {resp.status_code}")
        with _sync_lock:
            _sync_stats["erros"] += 1
        return

    data = resp.json()
    if not data.get("ok"):
        return

    if not data.get("tem_pendentes"):
        # Sem pendentes — apenas garante que proteções estao na chain
        # SEM flush, nao apaga regras existentes
        _garantir_protecoes(ips_protegidos)
        with _sync_lock:
            _sync_stats["polls_sem_mudanca"] += 1
            _sync_stats["sem_mudanca"]       += 1
        return

    rules = data.get("rules", [])

    # iface_map: local (config.json do sensor) tem prioridade sobre o do Django
    iface_final = {**data.get("iface_map", {}), **iface_map}

    hash_atual = _hash_regras(rules)
    if hash_atual == _hash_regras_aplicadas:
        logger.debug("[sync] Hash igual — sem mudança, confirmando")
        with _sync_lock:
            _sync_stats["polls_sem_mudanca"] += 1
            _sync_stats["sem_mudanca"]       += 1
        _confirmar(
            confirm_url, headers,
            [r["id"] for r in rules if "id" in r],
            True, "sem mudanca", session, session_lock,
        )
        return

    logger.info(
        f"[sync] Aplicando {len(rules)} regra(s) | "
        f"pendentes={data.get('pendentes', 0)} | "
        f"protegidos={ips_protegidos}"
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


# ══════════════════════════════════════════════════════════════════════════════
# APLICAR REGRAS VIA NFT
# ══════════════════════════════════════════════════════════════════════════════

def _aplicar_regras(rules: list, iface_map: dict, ips_protegidos: list):
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

        logger.info(f"[sync] {len(rules)} regra(s) aplicadas com sucesso")
        return True, f"{len(rules)} regras aplicadas"

    except subprocess.TimeoutExpired:
        logger.error("[sync] Timeout ao aplicar regras")
        return False, "Timeout ao aplicar regras"
    except FileNotFoundError:
        logger.error("[sync] nft não encontrado no sistema")
        return False, "nft não encontrado"
    except Exception as e:
        logger.error(f"[sync] Erro inesperado: {e}", exc_info=True)
        return False, str(e)
    finally:
        try:
            os.remove(TMP_NFT_FILE)
        except Exception:
            pass


def _contar_regras_ativas() -> int:
    try:
        result = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", "ms_rules"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.count(" drop") + result.stdout.count(" accept")
    except Exception:
        return 0


# ══════════════════════════════════════════════════════════════════════════════
# CONFIRMAR E RENOVAR TOKEN
# ══════════════════════════════════════════════════════════════════════════════

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