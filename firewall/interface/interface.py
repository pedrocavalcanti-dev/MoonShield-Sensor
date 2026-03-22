"""
firewall/interface/interface.py
──────────────────────────────────────────────────────────────────────
Telas TUI do módulo de firewall.

Expõe tela_firewall(cfg) que é chamado pelo menu_principal como
delegate — mesmo padrão de tela_instalar_suricata() e tela_diagnostico().

Submenu:
  [1] Instalar regras de monitoramento
  [2] Ver status das regras
  [3] Listar regras ativas (nft list)
  [4] Remover regras
  [5] Status do Agente HTTP (:8765)
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
from firewall.nucleo.instalador import (
    instalar_regras, remover_regras, listar_regras, obter_status,
)
import firewall.monitoramento.monitoramento as fw_mon
import firewall.monitoramento.sincronizador as fw_sync
import firewall.monitoramento.autoban       as fw_ban
import firewall.agente.agente               as fw_agente

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
        linha_texto("  [5]  --  Status do Agente HTTP (:8765)", C_MENU_TXT)
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
        elif opcao == "5":
            _tela_agente(cfg)
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
    linha_texto("  STATUS DO FIREWALL", C_TITULO)
    linha_vazia()

    # nftables
    status = obter_status()
    linha_texto("  -- nftables ----------------------------------------", C_NEON_DIM)
    linha_texto(
        f"  Disponivel : {'sim  ' + status['versao'] if status['nftables_ok'] else 'nao'}",
        C_OK if status["nftables_ok"] else C_ERRO,
    )
    linha_texto(
        f"  Instalado  : {'sim' if status['instalado'] else 'nao'}",
        C_OK if status["instalado"] else C_AVISO,
    )
    linha_texto(
        f"  Persistente: {'sim' if status['persistente'] else 'nao'}",
        C_OK if status["persistente"] else C_AVISO,
    )
    # v2: mostra chains se disponível
    chains = status.get("chains", {})
    if chains:
        chains_ok  = [c for c, v in chains.items() if v]
        chains_nok = [c for c, v in chains.items() if not v]
        if chains_ok:
            linha_texto(f"  Chains     : {', '.join(chains_ok)}", C_OK)
        if chains_nok:
            linha_texto(f"  Faltando   : {', '.join(chains_nok)}", C_ERRO)
    linha_vazia()

    # Monitoramento
    linha_texto("  -- Monitoramento -----------------------------------", C_NEON_DIM)
    fw_stats = fw_mon.obter_stats()
    linha_texto(
        f"  Rodando    : {'sim' if fw_stats['rodando'] else 'nao'}",
        C_OK if fw_stats["rodando"] else C_DIM,
    )
    linha_texto(f"  Vistos     : {fw_stats['vistos']:,}", C_DIM)
    linha_texto(
        f"  Enviados   : {fw_stats['enviados']:,}",
        C_OK if fw_stats["enviados"] > 0 else C_DIM,
    )
    linha_texto(f"  Drops      : {fw_stats.get('drops_sessao', 0):,}", C_AVISO)
    linha_texto(f"  Allows     : {fw_stats.get('allows_sessao', 0):,}", C_OK)
    linha_texto(
        f"  Erros      : {fw_stats['erros']:,}",
        C_ERRO if fw_stats["erros"] > 0 else C_DIM,
    )
    linha_texto(f"  Ultimo     : {fw_stats['ultimo']}", C_DIM)
    linha_vazia()

    # Sincronizador
    linha_texto("  -- Sincronizador -----------------------------------", C_NEON_DIM)
    sync_stats = fw_sync.obter_stats()
    linha_texto(
        f"  Rodando    : {'sim' if sync_stats['rodando'] else 'nao'}",
        C_OK if sync_stats["rodando"] else C_DIM,
    )
    linha_texto(
        f"  Aplicações : {sync_stats['aplicacoes']:,}",
        C_OK if sync_stats["aplicacoes"] > 0 else C_DIM,
    )
    linha_texto(f"  Regras nft : {sync_stats.get('regras_ativas', 0)}", C_DIM)
    linha_texto(f"  Ultimo     : {sync_stats['ultimo_apply']}", C_DIM)
    linha_texto(
        f"  Erros      : {sync_stats['erros']:,}",
        C_ERRO if sync_stats["erros"] > 0 else C_DIM,
    )
    linha_vazia()

    # Auto-ban
    linha_texto("  -- Auto-ban ----------------------------------------", C_NEON_DIM)
    ban_stats = fw_ban.obter_stats()
    linha_texto(
        f"  Bans sessão: {ban_stats.get('bans_sessao', ban_stats.get('total_bans', 0)):,}",
        C_AVISO if ban_stats.get("bans_sessao", ban_stats.get("total_bans", 0)) > 0 else C_DIM,
    )
    linha_texto(
        f"  Ativos agora: {ban_stats.get('ips_ativos', 0)}",
        C_AVISO if ban_stats.get("ips_ativos", 0) > 0 else C_DIM,
    )
    linha_texto(f"  Último IP  : {ban_stats.get('ultimo_ip', '—')}", C_DIM)
    linha_vazia()

    # Agente HTTP
    linha_texto("  -- Agente HTTP :8765 --------------------------------", C_NEON_DIM)
    ag_stats = fw_agente.obter_stats()
    linha_texto(
        f"  Rodando    : {'sim' if ag_stats['rodando'] else 'nao'}",
        C_OK if ag_stats["rodando"] else C_DIM,
    )
    linha_texto(f"  Chamadas   : {ag_stats['chamadas_total']:,}", C_DIM)
    linha_texto(
        f"  Ultima     : {ag_stats['ultima_chamada']} {ag_stats['ultimo_endpoint']}",
        C_DIM,
    )
    linha_texto(
        f"  Erros      : {ag_stats['erros']:,}",
        C_ERRO if ag_stats["erros"] > 0 else C_DIM,
    )
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


def _tela_agente(cfg: dict):
    cabecalho(cfg)
    linha_texto("  AGENTE HTTP LOCAL", C_TITULO)
    linha_vazia()

    ag_stats = fw_agente.obter_stats()
    rodando  = ag_stats["rodando"]

    linha_texto(
        f"  Status     : {'ATIVO' if rodando else 'INATIVO'}",
        C_OK if rodando else C_ERRO,
    )
    linha_texto(f"  Porta      : {ag_stats['porta']}", C_DIM)
    linha_texto(f"  Iniciado   : {ag_stats['iniciado_em']}", C_DIM)
    linha_texto(f"  Chamadas   : {ag_stats['chamadas_total']:,}", C_DIM)
    linha_texto(f"  Ultima     : {ag_stats['ultima_chamada']}", C_DIM)
    linha_texto(f"  Endpoint   : {ag_stats['ultimo_endpoint']}", C_DIM)
    linha_texto(
        f"  Erros      : {ag_stats['erros']:,}",
        C_ERRO if ag_stats["erros"] > 0 else C_DIM,
    )
    linha_vazia()

    if rodando:
        linha_texto(
            f"  Acesso     : http://localhost:{ag_stats['porta']}/status",
            C_NEON_DIM,
        )
        linha_texto(
            f"  Django URL : http://IP_SENSOR:{ag_stats['porta']}",
            C_NEON_DIM,
        )
    else:
        linha_texto(
            "  Agente nao iniciado — inicie o sensor com --auto",
            C_AVISO,
        )

    linha_vazia()
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