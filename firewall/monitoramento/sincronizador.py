"""
firewall/monitoramento/sincronizador.py
──────────────────────────────────────────────────────────────────────
v4: proteção contra auto-bloqueio do servidor MoonShield.
    Ao aplicar regras, sempre injeta uma regra de prioridade 0
    (acima de tudo) que garante acesso do IP do Django ao sensor.
    Isso impede que o painel perca acesso mesmo se alguém criar
    uma regra de bloqueio contra o IP do servidor Django.
──────────────────────────────────────────────────────────────────────
"""

import hashlib
import os
import subprocess
import threading
import time
import logging

from firewall.nucleo.conversor import gerar_script_nft, validar_iface_map

logger = logging.getLogger(__name__)

VERSAO_SINCRONIZADOR = "4.0"
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
}
_sync_lock = threading.Lock()
_hash_regras_aplicadas: str | None = None

# ══════════════════════════════════════════════════════════════════════════════
# PROTEÇÃO — IP do Django nunca pode ser bloqueado
# ══════════════════════════════════════════════════════════════════════════════

def _extrair_ip_django(moon_url: str) -> str | None:
    """Extrai o IP do servidor Django da URL configurada."""
    try:
        import re
        m = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', moon_url)
        return m.group(1) if m else None
    except Exception:
        return None


def _regra_protecao_django(ip_django: str) -> str:
    """
    Gera a linha nft que protege o IP do Django.
    Prioridade máxima — inserida ANTES de qualquer outra regra.
    Usa 'insert rule' em vez de 'add rule' para ficar no topo da chain.
    """
    return (
        f"# MOONSHIELD-PROTECTED: acesso do servidor Django sempre permitido\n"
        f"insert rule inet moonshield ms_rules ip saddr {ip_django} accept"
        f"  # [0] MOONSHIELD-PROTECTED"
    )


def _script_com_protecao(rules: list, iface_map: dict, ip_django: str | None) -> str:
    """
    Gera o script nft com a regra de proteção do Django inserida
    antes de todas as outras, se ip_django estiver disponível.
    """
    script = gerar_script_nft(rules, iface_map)

    if not ip_django:
        return script

    # Insere a regra de proteção logo após o "flush chain"
    linhas = script.splitlines()
    resultado = []
    for linha in linhas:
        resultado.append(linha)
        if linha.strip().startswith("flush chain inet moonshield ms_rules"):
            resultado.append("")
            resultado.append(_regra_protecao_django(ip_django))
            resultado.append("")

    return "\n".join(resultado)


# ══════════════════════════════════════════════════════════════════════════════
# INTERFACE PÚBLICA
# ══════════════════════════════════════════════════════════════════════════════

def _agora():
    from datetime import datetime
    return datetime.now().strftime("%H:%M:%S")


def _hash_conteudo_regras(rules: list) -> str:
    chave = sorted(
        f"{r.get('id')}|{r.get('action')}|{r.get('src')}|{r.get('dst')}|"
        f"{r.get('port')}|{r.get('priority')}|{r.get('enabled')}|"
        f"{r.get('iface')}|{r.get('proto')}|{r.get('dir')}"
        for r in rules
    )
    return hashlib.md5(str(chave).encode()).hexdigest()


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
            "rodando": True, "ultimo_poll": "—", "ultimo_apply": "—",
            "aplicacoes": 0, "erros": 0, "regras_ativas": 0,
            "ultima_versao": "—", "polls_sem_mudanca": 0,
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
# LOOP
# ══════════════════════════════════════════════════════════════════════════════

def _loop_sincronizador(cfg: dict, parar: threading.Event,
                        session, session_lock):
    pending_url = cfg["Moon_url"].rstrip("/") + PENDING_PATH
    confirm_url = cfg["Moon_url"].rstrip("/") + CONFIRM_PATH
    token       = cfg.get("token", "")
    headers     = {"X-MS-TOKEN": token}

    # Extrai e loga o IP protegido
    ip_django = _extrair_ip_django(cfg.get("Moon_url", ""))
    if ip_django:
        logger.info(f"[sync] Proteção ativa — IP Django {ip_django} sempre permitido")
    else:
        logger.warning("[sync] Não foi possível detectar IP do Django — proteção desativada")

    iface_map_inicial = cfg.get("iface_map") or {}
    if iface_map_inicial:
        for aviso in validar_iface_map(iface_map_inicial):
            logger.warning(f"[sync] {aviso}")

    logger.info(
        f"[sync] Iniciado v{VERSAO_SINCRONIZADOR} — poll a cada {POLL_INTERVAL}s"
    )

    while not parar.is_set():
        try:
            iface_map = cfg.get("iface_map", {"WAN": "eth0", "LAN": "eth1", "VPN": "tun0"})
            _poll_e_aplicar(pending_url, confirm_url, headers, iface_map,
                            session, session_lock, cfg, ip_django)
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
                    session, session_lock, cfg, ip_django=None):
    global _hash_regras_aplicadas

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

    rules       = data.get("rules", [])
    im_remoto   = data.get("iface_map", {})
    iface_final = {**im_remoto, **iface_map}

    hash_atual = _hash_conteudo_regras(rules)

    if hash_atual == _hash_regras_aplicadas:
        with _sync_lock:
            _sync_stats["polls_sem_mudanca"] += 1
        logger.debug("[sync] Regras sem mudança — skip")
        _confirmar(
            confirm_url, headers,
            [r["id"] for r in rules if "id" in r],
            True, "sem mudanca", session, session_lock,
        )
        return

    logger.info(f"[sync] {data.get('pendentes', 0)} pendente(s) — aplicando {len(rules)} regras")

    ok, msg = _aplicar_regras(rules, iface_final, ip_django)
    rule_ids = [r["id"] for r in rules if "id" in r]
    _confirmar(confirm_url, headers, rule_ids, ok, msg, session, session_lock)

    with _sync_lock:
        if ok:
            _hash_regras_aplicadas = hash_atual
            _sync_stats["aplicacoes"]   += 1
            _sync_stats["ultimo_apply"]  = _agora()
            _sync_stats["regras_ativas"] = _contar_regras_ativas()
            _sync_stats["ultima_versao"] = _agora()
        else:
            _sync_stats["erros"] += 1


def _aplicar_regras(rules: list, iface_map: dict,
                    ip_django: str | None = None) -> tuple[bool, str]:
    # Gera script com proteção do Django embutida
    script = _script_com_protecao(rules, iface_map, ip_django)
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
            logger.error(f"[sync] Script que falhou:\n{script}")
            return False, f"nft error: {err[:200]}"

        if ip_django:
            logger.info(f"[sync] {len(rules)} regras aplicadas ✓ | Django {ip_django} protegido")
        else:
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


def _contar_regras_ativas() -> int:
    try:
        result = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", "ms_rules"],
            capture_output=True, text=True, timeout=5,
        )
        count = result.stdout.count(" drop") + result.stdout.count(" accept")
        return count
    except Exception:
        return 0


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