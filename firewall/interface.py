"""
firewall/interface.py
──────────────────────────────────────────────────────────────────────
Telas TUI do módulo de firewall.

Expõe tela_firewall(cfg) que é chamado pelo menu_principal como
delegate — mesmo padrão de tela_instalar_suricata() e tela_diagnostico().

Submenu:
  [1] Instalar regras de monitoramento
  [2] Ver status das regras
  [3] Iniciar monitoramento (em thread — integra com tela_sensor)
  [4] Listar regras ativas
  [5] Remover regras
  [V] Voltar
──────────────────────────────────────────────────────────────────────
"""

import threading

from nucleo.interface import (
    cabecalho, topo, fundo, separador, separador_fino,
    linha_vazia, linha_texto, print_resultado, aguardar_enter,
    input_campo, spinner_inline,
    C_TITULO, C_WHITE, C_DIM, C_OK, C_ERRO, C_AVISO,
    C_MENU_TXT, C_NEON_DIM, C_NORMAL, LARGURA,
)
from firewall.instalador import (
    instalar_regras, remover_regras, listar_regras, obter_status,
)
import firewall.monitoramento as fw_mon

# ══════════════════════════════════════════════════════════════════════════════
# TELA PRINCIPAL DO FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

def tela_firewall(cfg: dict) -> dict:
    """
    Delegate chamado pelo menu_principal na opção [10].
    Exibe submenu do módulo de firewall.
    """
    while True:
        cabecalho(cfg)
        status = obter_status()
        _exibir_status_resumido(status)
        separador()

        linha_texto("  --- Firewall nftables ---------------------------------", C_NEON_DIM)
        linha_texto("  [1]  >>  Instalar regras de monitoramento", C_WHITE)
        linha_texto("  [2]  --  Ver status das regras", C_MENU_TXT)
        linha_texto("  [3]  --  Listar regras ativas (nft list)", C_MENU_TXT)
        linha_texto("  [4]  xx  Remover regras", C_AVISO)
        linha_vazia()
        linha_texto("  [V]  <<  Voltar ao menu principal", C_DIM)
        linha_vazia()
        fundo()

        print(C_AVISO + "  > Opcao: " + C_WHITE, end="")
        try:
            opcao = input().strip().upper()
        except (KeyboardInterrupt, EOFError):
            opcao = "V"

        if opcao == "1":
            _tela_instalar(cfg)
        elif opcao == "2":
            _tela_status(cfg)
        elif opcao == "3":
            _tela_listar(cfg)
        elif opcao == "4":
            _tela_remover(cfg)
        elif opcao == "V":
            break

    return cfg

# ══════════════════════════════════════════════════════════════════════════════
# SUBPÁGINAS
# ══════════════════════════════════════════════════════════════════════════════

def _tela_instalar(cfg: dict):
    cabecalho(cfg)
    linha_texto("  INSTALAR REGRAS DE MONITORAMENTO", C_TITULO)
    linha_vazia()
    linha_texto("  O sensor vai criar uma tabela 'moonshield' no nftables.", C_DIM)
    linha_texto("  Nao toca nas regras existentes do sistema.", C_DIM)
    linha_texto("  Monitora o FORWARD — trafego passando pelo gateway.", C_DIM)
    linha_vazia()

    status = obter_status()

    if not status["nftables_ok"]:
        print_resultado(False, "nftables nao encontrado no sistema.")
        linha_texto(f"  {status['versao']}", C_AVISO)
        aguardar_enter()
        return

    linha_texto(f"  nftables: {status['versao']}", C_OK)
    linha_vazia()

    if status["instalado"]:
        linha_texto("  AVISO: regras ja instaladas. Reinstalar vai sobrescrever.", C_AVISO)
        confirmar = input_campo("Continuar? (s/n)", "n")
        if confirmar.lower() != "s":
            aguardar_enter()
            return

    linha_vazia()
    ok, msg = spinner_inline("Instalando regras nftables...", instalar_regras)

    for linha in msg.split("\n"):
        if linha.strip():
            print_resultado(ok, linha.strip())

    aguardar_enter()


def _tela_status(cfg: dict):
    cabecalho(cfg)
    linha_texto("  STATUS DAS REGRAS DE FIREWALL", C_TITULO)
    linha_vazia()

    status = obter_status()

    linha_texto("  -- nftables ----------------------------------------", C_NEON_DIM)
    linha_texto(
        f"  Disponivel : {'sim  ' + status['versao'] if status['nftables_ok'] else 'nao'}",
        C_OK if status["nftables_ok"] else C_ERRO,
    )
    linha_texto(
        f"  Instalado  : {'sim' if status['instalado'] else 'nao — use [1] para instalar'}",
        C_OK if status["instalado"] else C_AVISO,
    )
    linha_texto(
        f"  Persistente: {'sim — sobrevive ao reboot' if status['persistente'] else 'nao — perdido no reboot'}",
        C_OK if status["persistente"] else C_AVISO,
    )
    linha_vazia()
    linha_texto("  -- Monitoramento -----------------------------------", C_NEON_DIM)

    fw_stats = fw_mon.obter_stats()
    rodando  = fw_stats["rodando"]

    linha_texto(
        f"  Loop ativo : {'sim' if rodando else 'nao'}",
        C_OK if rodando else C_DIM,
    )
    linha_texto(f"  Vistos     : {fw_stats['vistos']:,}", C_DIM)
    linha_texto(f"  Enviados   : {fw_stats['enviados']:,}", C_OK if fw_stats["enviados"] > 0 else C_DIM)
    linha_texto(f"  Erros      : {fw_stats['erros']:,}", C_ERRO if fw_stats["erros"] > 0 else C_DIM)
    linha_texto(f"  Ultimo env : {fw_stats['ultimo']}", C_DIM)
    linha_vazia()
    linha_texto("  -- Configuracao ------------------------------------", C_NEON_DIM)
    linha_texto(f"  Tabela     : {status['nome_tabela']}", C_DIM)
    linha_texto(f"  Prefixo    : {status['prefixo_log']}", C_DIM)
    linha_texto(f"  Endpoint   : /firewall/api/ingest/", C_DIM)
    linha_vazia()

    aguardar_enter()


def _tela_listar(cfg: dict):
    cabecalho(cfg)
    linha_texto("  REGRAS ATIVAS NO NFTABLES", C_TITULO)
    linha_vazia()

    ok, saida = spinner_inline("Consultando nft...", listar_regras)

    if not ok:
        print_resultado(False, saida)
    else:
        separador_fino()
        for l in saida.split("\n"):
            linha_texto(f"  {l}", C_DIM)
        separador_fino()

    aguardar_enter()


def _tela_remover(cfg: dict):
    cabecalho(cfg)
    linha_texto("  REMOVER REGRAS DE MONITORAMENTO", C_TITULO)
    linha_vazia()
    linha_texto("  Isso vai remover a tabela 'moonshield' do nftables", C_AVISO)
    linha_texto("  e apagar o arquivo de persistencia.", C_AVISO)
    linha_vazia()

    if fw_mon.esta_rodando():
        linha_texto("  AVISO: monitoramento esta rodando. Pare o sensor antes.", C_ERRO)
        aguardar_enter()
        return

    confirmar = input_campo("Confirma remocao? (s/n)", "n")
    if confirmar.lower() != "s":
        linha_texto("  Cancelado.", C_DIM)
        aguardar_enter()
        return

    linha_vazia()
    ok, msg = spinner_inline("Removendo regras...", remover_regras)
    print_resultado(ok, msg)
    aguardar_enter()

# ══════════════════════════════════════════════════════════════════════════════
# HELPER INTERNO
# ══════════════════════════════════════════════════════════════════════════════

def _exibir_status_resumido(status: dict):
    """Exibe linha de status resumida no cabeçalho do submenu."""
    if not status["nftables_ok"]:
        tag, cor = "[!!] nftables nao encontrado", C_ERRO
    elif not status["instalado"]:
        tag, cor = "[!!] regras nao instaladas",   C_AVISO
    elif not status["persistente"]:
        tag, cor = "[OK] ativo — sem persistencia", C_AVISO
    else:
        tag, cor = "[OK] ativo e persistente",      C_OK

    linha_texto(f"  Firewall  {tag}", cor)