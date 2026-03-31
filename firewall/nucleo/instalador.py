"""
firewall/nucleo/instalador.py
──────────────────────────────────────────────────────────────────────
Instala e remove as regras nftables de monitoramento do MoonShield.

Cria uma tabela isolada 'moonshield' com chains completas:
  ms_input     → filtra tráfego destinado à própria máquina (INPUT)
  ms_forward   → filtra tráfego roteado entre interfaces (FORWARD)
  ms_emergency → regras de emergência, avaliadas antes das normais
  ms_rules     → regras sincronizadas pelo painel (populadas pelo conversor)

v3: separação de tabelas (moonshield ≠ netforge), migração de NAT do
    iptables para nftables ao instalar, preservação da tabela netforge
    criada pelo ms_confignet.
──────────────────────────────────────────────────────────────────────
"""

import os
from pathlib import Path
from nucleo.utilitarios import run_cmd, cmd_existe, servico_ativo

# ══════════════════════════════════════════════════════════════════════════════
# VERSÃO
# ══════════════════════════════════════════════════════════════════════════════

VERSAO_INSTALADOR = "3.0"

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

PREFIXO_LOG  = "MS-FWD: "
NOME_TABELA  = "moonshield"

ARQUIVO_CONF     = Path("/etc/nftables.d/moonshield.conf")
ARQUIVO_CONF_ALT = Path("/etc/nftables.conf")

REGRAS = f"""\
# MoonShield — regras de monitoramento de firewall  v{VERSAO_INSTALADOR}
# Gerado automaticamente pelo ms_firewall.py
# Nao edite manualmente — use a opcao [0] do menu

table inet {NOME_TABELA} {{

    chain ms_input {{
        type filter hook input priority 0; policy accept;
        jump ms_emergency
        jump ms_rules
        log prefix "MS-INPUT: " flags all
    }}

    chain ms_forward {{
        type filter hook forward priority 0; policy accept;
        jump ms_emergency
        jump ms_rules
        log prefix "MS-FWD: " flags all
    }}

    chain ms_emergency {{
        # Reservado para bloqueios de emergência (auto-ban, SOC)
        # Populado pelo sensor — não edite manualmente
    }}

    chain ms_rules {{
        # Regras sincronizadas pelo painel MoonShield
        # Populado pelo sincronizador.py a cada poll
    }}

}}
"""

# ══════════════════════════════════════════════════════════════════════════════
# VERIFICAÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def verificar_nftables() -> tuple[bool, str]:
    if not cmd_existe("nft"):
        return False, "nftables nao encontrado — instale com: apt install nftables"
    code, out, _ = run_cmd("nft --version")
    if code == 0:
        return True, out.split("\n")[0].strip()
    return False, "nft encontrado mas nao respondeu"


def verificar_instalado() -> bool:
    code, _, _ = run_cmd(f"nft list table inet {NOME_TABELA}")
    return code == 0


def verificar_persistente() -> bool:
    if ARQUIVO_CONF.exists():
        return True
    if ARQUIVO_CONF_ALT.exists():
        return f"table inet {NOME_TABELA}" in ARQUIVO_CONF_ALT.read_text(encoding="utf-8")
    return False


def verificar_chains() -> dict[str, bool]:
    """v2: verifica se cada chain esperada existe na tabela."""
    chains_esperadas = ["ms_input", "ms_forward", "ms_emergency", "ms_rules"]
    resultado = {}
    if not verificar_instalado():
        return {c: False for c in chains_esperadas}
    _, out, _ = run_cmd(f"nft list table inet {NOME_TABELA}")
    for chain in chains_esperadas:
        resultado[chain] = f"chain {chain}" in out
    return resultado


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO E MIGRAÇÃO DE NAT (iptables → nftables)
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_nat_iptables() -> list[dict]:
    """
    Lê regras MASQUERADE/SNAT do iptables antes de subir o nftables.
    Retorna lista de {'iface_out': 'enp0s3'} para cada regra encontrada.
    Formato da linha: pkts bytes target prot opt in out src dst [options]
    """
    regras = []
    try:
        code, out, _ = run_cmd("iptables -t nat -L POSTROUTING -n -v")
        if code != 0:
            return []
        for linha in out.splitlines():
            if "MASQUERADE" not in linha and "SNAT" not in linha:
                continue
            partes = linha.split()
            # colunas: pkts bytes target prot opt in out src dst ...
            if len(partes) >= 7:
                iface_out = partes[6]
                if iface_out and iface_out != "*":
                    # Evita duplicatas
                    if not any(r["iface_out"] == iface_out for r in regras):
                        regras.append({"iface_out": iface_out})
    except Exception:
        pass
    return regras


def _detectar_ip_forward() -> bool:
    code, out, _ = run_cmd("sysctl net.ipv4.ip_forward")
    return "= 1" in out if code == 0 else False


def _migrar_nat_para_nft(regras_nat: list[dict]):
    """
    Cria chain ms_nat na tabela moonshield e adiciona MASQUERADE
    para cada interface que tinha no iptables.
    Usa família inet para compatibilidade com kernels >= 5.2.
    """
    if not regras_nat:
        return

    # Cria chain NAT se não existir
    run_cmd(
        "nft add chain inet moonshield ms_nat "
        "{ type nat hook postrouting priority 100 ; }",
        silencioso=True,
    )

    for r in regras_nat:
        iface = r["iface_out"]
        run_cmd(
            f'nft add rule inet moonshield ms_nat oifname "{iface}" masquerade',
            silencioso=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# PRESERVAÇÃO DA TABELA NETFORGE (ms_confignet)
# ══════════════════════════════════════════════════════════════════════════════

def _preservar_roteamento_netforge():
    """
    Garante que a tabela 'netforge' (criada pelo ms_confignet) nunca é
    tocada pelo instalador do MoonShield.

    Esta função apenas verifica a existência da tabela para fins de log.
    O instalador do MoonShield opera exclusivamente na tabela 'moonshield'
    e nunca emite flush ruleset completo — por isso a netforge está sempre
    preservada por design.
    """
    code, out, _ = run_cmd("nft list tables", silencioso=True)
    if code == 0 and "netforge" in out:
        # Tabela netforge presente — não tocamos nela
        pass


# ══════════════════════════════════════════════════════════════════════════════
# INSTALAR
# ══════════════════════════════════════════════════════════════════════════════

def instalar_regras() -> tuple[bool, str]:
    ok, msg = verificar_nftables()
    if not ok:
        return False, msg

    # ── Snapshot do estado ANTES de qualquer mudança ─────────────────────────
    ip_forward_ativo = _detectar_ip_forward()
    nat_existente    = _detectar_nat_iptables()

    if verificar_instalado():
        remover_regras(silencioso=True)

    tmp = "/tmp/ms_fw_rules.nft"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(REGRAS)
        code, _, err = run_cmd(f"nft -f {tmp}")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    if code != 0:
        return False, f"Erro ao aplicar regras: {err}"

    if not verificar_instalado():
        return False, "Regras enviadas mas tabela nao encontrada — verifique com: nft list tables"

    # v2: verifica se todas as chains foram criadas
    chains = verificar_chains()
    chains_faltando = [c for c, ok in chains.items() if not ok]
    if chains_faltando:
        return False, f"Tabela criada mas chains ausentes: {', '.join(chains_faltando)}"

    # ── Migra NAT do iptables para nftables ──────────────────────────────────
    if nat_existente:
        _migrar_nat_para_nft(nat_existente)
        if ip_forward_ativo:
            run_cmd("sysctl -w net.ipv4.ip_forward=1", silencioso=True)

    # ── Preserva tabela netforge (ms_confignet) — nunca a tocamos ────────────
    _preservar_roteamento_netforge()

    ok_p, msg_p = _tornar_persistente()

    resultado = f"Regras instaladas com sucesso (v{VERSAO_INSTALADOR})."
    if nat_existente:
        ifaces = [r["iface_out"] for r in nat_existente]
        resultado += f"\nNAT migrado do iptables: {', '.join(ifaces)}"
    if ok_p:
        resultado += f"\nPersistencia configurada em: {msg_p}"
    else:
        resultado += f"\nAVISO: persistencia falhou — regras serao perdidas no reboot.\n{msg_p}"

    return True, resultado


def remover_regras(silencioso: bool = False) -> tuple[bool, str]:
    if not verificar_instalado():
        if not silencioso:
            return True, "Tabela moonshield nao encontrada — nada a remover."
        return True, ""

    code, _, err = run_cmd(f"nft delete table inet {NOME_TABELA}")
    if code != 0:
        return False, f"Erro ao remover tabela: {err}"

    _remover_persistencia()

    if not silencioso:
        return True, "Regras removidas com sucesso."
    return True, ""


def listar_regras() -> tuple[bool, str]:
    if not verificar_instalado():
        return False, "Tabela moonshield nao esta instalada."
    code, out, err = run_cmd(f"nft list table inet {NOME_TABELA}")
    if code == 0:
        return True, out.strip()
    return False, f"Erro ao listar regras: {err}"


def obter_status() -> dict:
    """v3: inclui versao_instalador, status das chains e presença da tabela netforge."""
    disponivel, versao = verificar_nftables()
    instalado          = verificar_instalado() if disponivel else False
    persistente        = verificar_persistente() if instalado else False
    chains             = verificar_chains() if instalado else {}

    # Detecta se o ms_confignet está ativo
    netforge_ativa = False
    if disponivel:
        code, out, _ = run_cmd("nft list tables", silencioso=True)
        netforge_ativa = code == 0 and "netforge" in out

    return {
        "nftables_ok":        disponivel,
        "versao":             versao if disponivel else "—",
        "instalado":          instalado,
        "persistente":        persistente,
        "prefixo_log":        PREFIXO_LOG,
        "nome_tabela":        NOME_TABELA,
        "versao_instalador":  VERSAO_INSTALADOR,
        "chains":             chains,
        "netforge_ativa":     netforge_ativa,
    }


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTÊNCIA
# ══════════════════════════════════════════════════════════════════════════════

def _tornar_persistente() -> tuple[bool, str]:
    dir_d = Path("/etc/nftables.d")

    if dir_d.exists():
        try:
            ARQUIVO_CONF.write_text(REGRAS, encoding="utf-8")
            _garantir_include()
            _habilitar_servico()
            return True, str(ARQUIVO_CONF)
        except Exception as e:
            return False, str(e)
    else:
        try:
            atual = ARQUIVO_CONF_ALT.read_text(encoding="utf-8") if ARQUIVO_CONF_ALT.exists() else ""
            limpo = _remover_bloco_anterior(atual)
            ARQUIVO_CONF_ALT.write_text(limpo.rstrip() + "\n\n" + REGRAS, encoding="utf-8")
            _habilitar_servico()
            return True, str(ARQUIVO_CONF_ALT)
        except Exception as e:
            return False, str(e)


def _garantir_include():
    if not ARQUIVO_CONF_ALT.exists():
        return
    conteudo = ARQUIVO_CONF_ALT.read_text(encoding="utf-8")
    include  = 'include "/etc/nftables.d/*.conf"'
    if include not in conteudo:
        with open(ARQUIVO_CONF_ALT, "a", encoding="utf-8") as f:
            f.write(f"\n{include}\n")


def _remover_bloco_anterior(conteudo: str) -> str:
    linhas    = conteudo.split("\n")
    resultado = []
    dentro    = False
    profund   = 0

    for linha in linhas:
        if f"table inet {NOME_TABELA}" in linha and not dentro:
            dentro  = True
            profund = 0
        if dentro:
            profund += linha.count("{") - linha.count("}")
            if profund <= 0 and ("{" in linha or profund < 0):
                dentro = False
            continue
        resultado.append(linha)

    return "\n".join(resultado)


def _remover_persistencia():
    if ARQUIVO_CONF.exists():
        try:
            ARQUIVO_CONF.unlink()
        except Exception:
            pass
    elif ARQUIVO_CONF_ALT.exists():
        try:
            atual = ARQUIVO_CONF_ALT.read_text(encoding="utf-8")
            ARQUIVO_CONF_ALT.write_text(_remover_bloco_anterior(atual), encoding="utf-8")
        except Exception:
            pass


def _habilitar_servico():
    run_cmd("systemctl enable nftables")
    run_cmd("systemctl start  nftables")