"""
firewall/sincronizador.py  (roda no sensor Linux, não no Django)
──────────────────────────────────────────────────────────────────────
v5: proteção automática de IPs críticos — sem hardcode.

  - IP do Django   → extraído da Moon_url (ex: http://192.168.0.105/...)
  - IP do sensor   → detectado via UDP trick (qual IP o kernel usaria
                     para sair à rede) — nunca hardcodado
  - IP do gateway  → lido da tabela de roteamento do Linux

  Ao aplicar regras, injeta ANTES de tudo:
    insert rule inet moonshield ms_rules ip saddr <IP_DJANGO>  accept
    insert rule inet moonshield ms_rules ip saddr <IP_SENSOR>  accept
    insert rule inet moonshield ms_rules ip saddr <IP_GATEWAY> accept

  Isso garante que mesmo que alguém crie DENY any, esses IPs
  críticos sempre conseguem se comunicar.
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

from .conversor import gerar_script_nft, validar_iface_map

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
_hash_regras_aplicadas: str | None = None


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO AUTOMÁTICA DE IPs CRÍTICOS
# ══════════════════════════════════════════════════════════════════════════════

def _ip_do_django(moon_url: str) -> str | None:
    """Extrai o IP do servidor Django da Moon_url configurada."""
    try:
        m = re.search(r'https?://(\d+\.\d+\.\d+\.\d+)', moon_url)
        return m.group(1) if m else None
    except Exception:
        return None


def _ip_do_sensor() -> str | None:
    """
    Detecta o IP local do sensor via UDP trick.
    Pergunta ao kernel qual IP usaria para sair à rede — não manda
    nenhum pacote, só consulta a tabela de roteamento.
    Funciona independente do nome da interface ou configuração.
    """
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


def _ip_do_gateway() -> str | None:
    """
    Lê o gateway padrão da tabela de roteamento do Linux.
    Usa `ip route` para não depender de config manual.
    """
    try:
        result = subprocess.run(
            ['ip', 'route', 'show', 'default'],
            capture_output=True, text=True, timeout=3,
        )
        # Formato: "default via 192.168.0.1 dev eth0 ..."
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def _coletar_ips_protegidos(moon_url: str) -> list[str]:
    """
    Coleta todos os IPs que devem ser protegidos (nunca bloqueados).
    Retorna lista de IPs únicos detectados automaticamente.
    """
    ips = []

    ip_django = _ip_do_django(moon_url)
    if ip_django:
        ips.append(ip_django)
        logger.info(f"[sync] IP Django detectado: {ip_django}")
    else:
        logger.warning("[sync] Não foi possível extrair IP do Django da Moon_url")

    ip_sensor = _ip_do_sensor()
    if ip_sensor:
        # Evita duplicata se Django e sensor rodarem na mesma máquina
        if ip_sensor not in ips:
            ips.append(ip_sensor)
        logger.info(f"[sync] IP Sensor detectado: {ip_sensor}")
    else:
        logger.warning("[sync] Não foi possível detectar IP do sensor")

    ip_gateway = _ip_do_gateway()
    if ip_gateway:
        if ip_gateway not in ips:
            ips.append(ip_gateway)
        logger.info(f"[sync] IP Gateway detectado: {ip_gateway}")
    else:
        logger.warning("[sync] Não foi possível detectar gateway padrão")

    return ips


# ══════════════════════════════════════════════════════════════════════════════
# GERAÇÃO DO SCRIPT COM PROTEÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _linhas_protecao(ips_protegidos: list[str]) -> list[str]:
    """
    Gera as linhas nft que garantem acesso dos IPs críticos.
    Usa 'insert' para que fiquem sempre no topo da chain,
    acima de qualquer regra DENY criada pelo usuário.
    """
    if not ips_protegidos:
        return []

    linhas = [
        "# ── MOONSHIELD: IPs críticos sempre permitidos (auto-detectados) ──",
    ]
    for ip in ips_protegidos:
        linhas.append(
            f"insert rule inet moonshield ms_rules "
            f"ip saddr {ip} accept  "
            f"# protegido automaticamente"
        )
    linhas.append("")
    return linhas


def _script_com_protecao(rules: list, iface_map: dict,
                          ips_protegidos: list[str]) -> str:
    """
    Gera o script nft com as regras de proteção inseridas
    logo após o flush chain, antes de qualquer outra regra.
    """
    script = gerar_script_nft(rules, iface_map)

    if not ips_protegidos:
        return script

    linhas_prot = _linhas_protecao(ips_protegidos)
    linhas      = script.splitlines()
    resultado   = []

    for linha in linhas:
        resultado.append(linha)
        if linha.strip().startswith("flush chain inet moonshield ms_rules"):
            resultado.append("")
            resultado.extend(linhas_prot)

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

def _loop_sincronizador(cfg: dict, parar: threading.Event,
                        session, session_lock):
    pending_url = cfg["Moon_url"].rstrip("/") + PENDING_PATH
    confirm_url = cfg["Moon_url"].rstrip("/") + CONFIRM_PATH
    token       = cfg.get("token", "")
    headers     = {"X-MS-TOKEN": token}

    # Detecta todos os IPs críticos automaticamente ao iniciar
    ips_protegidos = _coletar_ips_protegidos(cfg.get("Moon_url", ""))

    with _sync_lock:
        _sync_stats["ips_protegidos"] = ips_protegidos

    if ips_protegidos:
        logger.info(f"[sync] IPs protegidos: {', '.join(ips_protegidos)}")
    else:
        logger.warning("[sync] Nenhum IP crítico detectado — proteção desativada")

    # Valida iface_map se veio no config
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
    # iface_map local (config.json) tem prioridade sobre o remoto
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

    logger.info(
        f"[sync] {data.get('pendentes', 0)} pendente(s) — "
        f"aplicando {len(rules)} regras | "
        f"protegendo: {', '.join(ips_protegidos) or '—'}"
    )

    ok, msg  = _aplicar_regras(rules, iface_final, ips_protegidos)
    rule_ids = [r["id"] for r in rules if "id" in r]
    _confirmar(confirm_url, headers, rule_ids, ok, msg, session, session_lock)

    with _sync_lock:
        if ok:
            _hash_regras_aplicadas       = hash_atual
            _sync_stats["aplicacoes"]   += 1
            _sync_stats["ultimo_apply"]  = _agora()
            _sync_stats["regras_ativas"] = _contar_regras_ativas()
            _sync_stats["ultima_versao"] = _agora()
        else:
            _sync_stats["erros"] += 1


def _aplicar_regras(rules: list, iface_map: dict,
                    ips_protegidos: list[str]) -> tuple[bool, str]:
    """Gera script nft com proteção e aplica via nft -f."""
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
            logger.error(f"[sync] nft -f falhou: {err}")
            logger.error(f"[sync] Script:\n{script}")
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


def _contar_regras_ativas() -> int:
    try:
        result = subprocess.run(
            ["nft", "list", "chain", "inet", "moonshield", "ms_rules"],
            capture_output=True, text=True, timeout=5,
        )
        return result.stdout.count(" drop") + result.stdout.count(" accept")
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