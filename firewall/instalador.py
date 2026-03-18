"""
firewall/instalador.py
──────────────────────────────────────────────────────────────────────
Instala e remove as regras nftables de monitoramento do MoonShield.

Cria uma tabela isolada 'moonshield' com uma chain FORWARD que loga
todo o tráfego passando pelo gateway com prefixo 'MS-FWD: '.
Não toca nas regras existentes do sistema.

Persiste via /etc/nftables.d/moonshield.conf (ou /etc/nftables.conf
como fallback).

FIX: chain renomeada de 'monitor' para 'ms_forward' —
     'monitor' é palavra reservada no nftables v1.0+ e causa
     syntax error ao tentar aplicar as regras.
──────────────────────────────────────────────────────────────────────
"""

import os
from pathlib import Path
from nucleo.utilitarios import run_cmd, cmd_existe, servico_ativo

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

PREFIXO_LOG  = "MS-FWD: "
NOME_TABELA  = "moonshield"

ARQUIVO_CONF     = Path("/etc/nftables.d/moonshield.conf")
ARQUIVO_CONF_ALT = Path("/etc/nftables.conf")

# 'monitor' é palavra reservada no nftables — usar 'ms_forward' como nome da chain
REGRAS = f"""\
# MoonShield — regras de monitoramento de firewall
# Gerado automaticamente pelo ms_firewall.py
# Nao edite manualmente — use a opcao [0] do menu

table inet {NOME_TABELA} {{
    chain ms_forward {{
        type filter hook forward priority 0; policy accept;
        log prefix "{PREFIXO_LOG}" flags all
    }}
}}
"""

# ══════════════════════════════════════════════════════════════════════════════
# VERIFICAÇÕES
# ══════════════════════════════════════════════════════════════════════════════

def verificar_nftables() -> tuple[bool, str]:
    """Verifica se nftables está disponível. Retorna (ok, msg)."""
    if not cmd_existe("nft"):
        return False, "nftables nao encontrado — instale com: apt install nftables"
    code, out, _ = run_cmd("nft --version")
    if code == 0:
        return True, out.split("\n")[0].strip()
    return False, "nft encontrado mas nao respondeu"


def verificar_instalado() -> bool:
    """Verifica se a tabela moonshield já existe no nftables."""
    code, _, _ = run_cmd(f"nft list table inet {NOME_TABELA}")
    return code == 0


def verificar_persistente() -> bool:
    """Verifica se as regras estão salvas para o reboot."""
    if ARQUIVO_CONF.exists():
        return True
    if ARQUIVO_CONF_ALT.exists():
        return f"table inet {NOME_TABELA}" in ARQUIVO_CONF_ALT.read_text(encoding="utf-8")
    return False

# ══════════════════════════════════════════════════════════════════════════════
# INSTALAR
# ══════════════════════════════════════════════════════════════════════════════

def instalar_regras() -> tuple[bool, str]:
    """
    Instala a tabela moonshield no nftables.
    Retorna (ok, mensagem).
    """
    ok, msg = verificar_nftables()
    if not ok:
        return False, msg

    # Remove anterior se existir (reinstalação limpa)
    if verificar_instalado():
        remover_regras(silencioso=True)

    # Grava em arquivo temporário e aplica (mais confiável que echo+pipe)
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

    ok_p, msg_p = _tornar_persistente()

    resultado = "Regras instaladas com sucesso."
    if ok_p:
        resultado += f"\nPersistencia configurada em: {msg_p}"
    else:
        resultado += f"\nAVISO: persistencia falhou — regras serao perdidas no reboot.\n{msg_p}"

    return True, resultado


def remover_regras(silencioso: bool = False) -> tuple[bool, str]:
    """Remove a tabela moonshield do nftables. Retorna (ok, mensagem)."""
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
    """Retorna o conteúdo atual da tabela moonshield."""
    if not verificar_instalado():
        return False, "Tabela moonshield nao esta instalada."
    code, out, err = run_cmd(f"nft list table inet {NOME_TABELA}")
    if code == 0:
        return True, out.strip()
    return False, f"Erro ao listar regras: {err}"


def obter_status() -> dict:
    """Retorna dict com status atual. Usado pelo menu."""
    disponivel, versao = verificar_nftables()
    instalado    = verificar_instalado() if disponivel else False
    persistente  = verificar_persistente() if instalado else False

    return {
        "nftables_ok":   disponivel,
        "versao":        versao if disponivel else "—",
        "instalado":     instalado,
        "persistente":   persistente,
        "prefixo_log":   PREFIXO_LOG,
        "nome_tabela":   NOME_TABELA,
    }

# ══════════════════════════════════════════════════════════════════════════════
# PERSISTÊNCIA
# ══════════════════════════════════════════════════════════════════════════════

def _tornar_persistente() -> tuple[bool, str]:
    """Salva as regras para sobreviver ao reboot."""
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
    """Garante que /etc/nftables.conf inclui o diretório nftables.d."""
    if not ARQUIVO_CONF_ALT.exists():
        return
    conteudo = ARQUIVO_CONF_ALT.read_text(encoding="utf-8")
    include  = 'include "/etc/nftables.d/*.conf"'
    if include not in conteudo:
        with open(ARQUIVO_CONF_ALT, "a", encoding="utf-8") as f:
            f.write(f"\n{include}\n")


def _remover_bloco_anterior(conteudo: str) -> str:
    """Remove bloco moonshield anterior do nftables.conf."""
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
    """Remove arquivo de persistência dedicado."""
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
    """Habilita o serviço nftables no boot."""
    run_cmd("systemctl enable nftables")
    run_cmd("systemctl start  nftables")