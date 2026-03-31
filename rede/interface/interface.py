"""
interface.py
Menus TUI do painel de configuração de rede MoonShield.

Estrutura de menus:
  menu_principal()
    ├── menu_interfaces()       — configurar IP/DHCP em interfaces físicas
    ├── menu_vlans()            — gerenciar VLANs (cadastrar, aplicar, remover)
    ├── menu_roteamento()       — NAT, ip_forward, aplicar roteamento completo
    │     └── [5] roteamento direto entre interfaces físicas (sem VLAN)
    ├── menu_relay()            — configurar e controlar DHCP relay
    ├── menu_configuracoes()    — trunk, WAN, servidor DHCP
    └── menu_status()           — status completo da rede
"""

import re
import subprocess
import sys

from .tui import (
    cabecalho, fundo, separador, linha_texto, linha_vazia,
    print_ok, print_erro, print_aviso, print_info,
    input_campo, aguardar_enter, ler_opcao,
    exibir_resultados, resumo_resultados,
    C_TITULO, C_DIM, C_WHITE, C_OK, C_ERRO, C_AVISO, C_NEON,
)
from ..nucleo import persistencia as db
from ..nucleo import vlan as vlan_mod
from ..nucleo import roteador as rot
from ..nucleo import relay as relay_mod
from ..nucleo.utilitarios import (
    validar_ip, validar_cidr, validar_vlan_id, ip_na_rede,
    listar_interfaces_sistema, gateway_padrao, ip_da_interface,
    interface_existe, rodar,
)


# ══════════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def menu_principal():
    while True:
        config = db.carregar()
        cabecalho()

        trunk = config.get("trunk_interface", "—")
        wan   = config.get("wan_interface", "—")
        dhcp  = config.get("dhcp_server", "—") or "—"
        vlans = config.get("vlans", [])
        fw    = rot.status_ip_forward()
        rel   = relay_mod.status_relay()

        linha_texto("  -- Status rápido -------------------------------------", C_NEON)
        linha_texto(f"  Trunk  : {trunk}    WAN: {wan}", C_DIM)
        linha_texto(f"  VLANs  : {len(vlans)} configurada(s)", C_DIM)
        linha_texto(f"  DHCP Srv: {dhcp}", C_DIM)

        fw_cor = C_OK if fw == "1" else C_ERRO
        linha_texto(f"  ip_forward: {fw}   Relay: {'ATIVO' if rel['ativo'] else 'PARADO'}", fw_cor)

        separador()
        linha_texto("  [1]  Interfaces físicas  (IP / DHCP)", C_WHITE)
        linha_texto("  [2]  VLANs  (cadastrar / aplicar / remover)", C_WHITE)
        linha_texto("  [3]  Roteamento / NAT", C_WHITE)
        linha_texto("  [4]  DHCP Relay", C_WHITE)
        linha_texto("  [5]  Configurações gerais  (trunk / WAN / DHCP srv)", C_WHITE)
        linha_texto("  [6]  Status completo da rede", C_WHITE)
        linha_vazia()
        linha_texto("  [V]  Sair", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()

        if   op == "1": menu_interfaces()
        elif op == "2": menu_vlans()
        elif op == "3": menu_roteamento()
        elif op == "4": menu_relay()
        elif op == "5": menu_configuracoes()
        elif op == "6": menu_status()
        elif op == "V":
            from .tui import limpar
            limpar()
            print(C_DIM + "\n  MoonShield ConfigNet encerrado.\n" + C_DIM.__class__.__name__)
            sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# MENU — INTERFACES FÍSICAS
# ══════════════════════════════════════════════════════════════════════════════

def menu_interfaces():
    while True:
        ifaces = _listar_ifaces_com_info()
        cabecalho("Interfaces físicas")
        linha_texto("  #   INTERFACE    IP               MASCARA  ESTADO", C_DIM)
        separador()
        for i, iface in enumerate(ifaces):
            cor = C_OK if iface["estado"] == "UP" else C_ERRO
            linha_texto(
                f"  [{i+1}]  {iface['nome'].ljust(10)} {iface['ip'].ljust(16)} "
                f"/{iface['mask'].ljust(4)} {iface['estado']}", cor
            )
        linha_vazia()
        linha_texto("  Digite o número para configurar ou [V] para voltar.", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao("Interface ou [V]")
        if op == "V":
            return
        if op.isdigit():
            idx = int(op) - 1
            if 0 <= idx < len(ifaces):
                _configurar_interface_fisica(ifaces[idx])
            else:
                print_erro("Número inválido.")
                aguardar_enter()


def _configurar_interface_fisica(iface: dict):
    while True:
        cabecalho(f"Configurar: {iface['nome']}")
        linha_texto(f"  IP atual : {iface['ip']}", C_DIM)
        linha_texto(f"  Máscara  : /{iface['mask']}", C_DIM)
        linha_texto(f"  Estado   : {iface['estado']}", C_DIM)
        linha_vazia()
        linha_texto("  [1]  IP estático", C_WHITE)
        linha_texto("  [2]  DHCP", C_WHITE)
        linha_texto("  [3]  Ativar interface", C_WHITE)
        linha_texto("  [4]  Desativar interface", C_AVISO)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if op == "V":
            return
        elif op == "1":
            _aplicar_ip_estatico(iface)
        elif op == "2":
            _aplicar_dhcp(iface)
        elif op == "3":
            _ativar_iface(iface["nome"])
        elif op == "4":
            _desativar_iface(iface["nome"])


def _aplicar_ip_estatico(iface: dict):
    cabecalho(f"IP Estático — {iface['nome']}")
    ip      = input_campo("IP", iface["ip"] if iface["ip"] != "—" else "")
    mascara = input_campo("Máscara (bits)", iface["mask"] if iface["mask"] != "—" else "24")
    gw      = input_campo("Gateway (vazio = sem gateway)", gateway_padrao() or "")

    if not ip or not validar_ip(ip):
        print_erro("IP inválido.")
        aguardar_enter()
        return

    print()
    _limpar_iface(iface["nome"])
    rodar(["ip", "link", "set", iface["nome"], "up"], silencioso=True)

    ok, _, err = rodar(["ip", "addr", "add", f"{ip}/{mascara}", "dev", iface["nome"]])
    if ok:
        print_ok(f"IP {ip}/{mascara} aplicado em {iface['nome']}")
    else:
        print_erro(f"Erro: {err}")
        aguardar_enter()
        return

    if gw:
        rodar(["ip", "route", "del", "default"], silencioso=True)
        ok2, _, err2 = rodar(["ip", "route", "add", "default", "via", gw])
        if ok2:
            print_ok(f"Gateway {gw} configurado")
        else:
            print_aviso(f"Gateway não aplicado: {err2}")

    aguardar_enter()


def _aplicar_dhcp(iface: dict):
    cabecalho(f"DHCP — {iface['nome']}")
    print_info(f"Solicitando IP via DHCP em {iface['nome']}...")
    print()
    _limpar_iface(iface["nome"])
    rodar(["ip", "link", "set", iface["nome"], "up"], silencioso=True)

    ok_dc, _, _ = rodar(["which", "dhclient"], silencioso=True)
    if ok_dc:
        print_info("Usando dhclient...")
        ok, _, err = rodar(["dhclient", iface["nome"]])
        if ok:
            print_ok(f"DHCP aplicado em {iface['nome']}")
        else:
            print_erro(f"dhclient falhou: {err[:80]}")
    else:
        ok_ud, _, _ = rodar(["which", "udhcpc"], silencioso=True)
        if ok_ud:
            print_info("Usando udhcpc...")
            ok, _, err = rodar(["udhcpc", "-i", iface["nome"], "-q"])
            if ok:
                print_ok(f"DHCP aplicado em {iface['nome']}")
            else:
                print_erro(f"udhcpc falhou: {err[:80]}")
        else:
            print_erro("Nenhum cliente DHCP encontrado (dhclient ou udhcpc).")

    aguardar_enter()


def _ativar_iface(nome: str):
    ok, _, err = rodar(["ip", "link", "set", nome, "up"])
    print_ok(f"Interface {nome} ativada") if ok else print_erro(f"Erro: {err}")
    aguardar_enter()


def _desativar_iface(nome: str):
    _limpar_iface(nome)
    ok, _, err = rodar(["ip", "link", "set", nome, "down"])
    print_ok(f"Interface {nome} desativada") if ok else print_erro(f"Erro: {err}")
    aguardar_enter()


def _limpar_iface(nome: str):
    """Remove IPs, rotas e processos DHCP de uma interface."""
    rodar(f"pkill -f 'dhclient.*{nome}'", silencioso=True)
    rodar(f"pkill -f 'udhcpc.*{nome}'", silencioso=True)
    rodar(["dhclient", "-r", nome], silencioso=True)
    ok, rotas, _ = rodar(f"ip route show dev {nome}", silencioso=True)
    if ok and rotas:
        for rota in rotas.splitlines():
            rodar(f"ip route del {rota.split()[0]} dev {nome}", silencioso=True)
    ok2, dr, _ = rodar(["ip", "route", "show", "default"], silencioso=True)
    if ok2 and nome in dr:
        rodar(["ip", "route", "del", "default"], silencioso=True)
    rodar(["ip", "addr", "flush", "dev", nome], silencioso=True)


# ══════════════════════════════════════════════════════════════════════════════
# MENU — VLANs
# ══════════════════════════════════════════════════════════════════════════════

def menu_vlans():
    while True:
        config = db.carregar()
        vlans  = config.get("vlans", [])
        trunk  = config.get("trunk_interface", "—")
        cabecalho("VLANs")

        linha_texto(f"  Trunk: {trunk}", C_DIM)
        linha_vazia()

        if vlans:
            linha_texto("  ID    NOME            REDE              GATEWAY       STATUS", C_DIM)
            separador()
            for v in vlans:
                ativo = vlan_mod.subinterface_ativa(trunk, v["id"])
                cor   = C_OK if ativo else C_AVISO
                status = "UP" if ativo else "DOWN"
                linha_texto(
                    f"  {str(v['id']).ljust(5)} {v['nome'].ljust(15)} "
                    f"{v['rede'].ljust(17)} {v['gateway'].ljust(13)} {status}", cor
                )
        else:
            linha_texto("  Nenhuma VLAN cadastrada.", C_DIM)

        linha_vazia()
        separador()
        linha_texto("  [1]  Cadastrar nova VLAN", C_WHITE)
        linha_texto("  [2]  Aplicar todas as VLANs no sistema", C_WHITE)
        linha_texto("  [3]  Remover VLAN", C_WHITE)
        linha_texto("  [4]  Remover todas as VLANs do sistema", C_AVISO)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if   op == "V": return
        elif op == "1": _cadastrar_vlan(config)
        elif op == "2": _aplicar_vlans(config)
        elif op == "3": _remover_vlan_menu(config)
        elif op == "4": _remover_todas_vlans(config)


def _cadastrar_vlan(config: dict):
    cabecalho("Cadastrar VLAN")

    id_str = input_campo("ID da VLAN (1-4094)")
    if not id_str.isdigit() or not validar_vlan_id(int(id_str)):
        print_erro("ID de VLAN inválido (1–4094).")
        aguardar_enter()
        return
    vlan_id = int(id_str)

    if db.buscar_vlan(vlan_id):
        print_erro(f"VLAN {vlan_id} já existe.")
        aguardar_enter()
        return

    nome    = input_campo("Nome da VLAN (ex: CPD, VoIP, Usuarios)")
    rede    = input_campo("Rede CIDR (ex: 10.10.10.0/24)")
    gateway = input_campo("IP do gateway nesta VLAN (ex: 10.10.10.1)")

    erros = []
    if not nome:
        erros.append("Nome obrigatório.")
    if not validar_cidr(rede):
        erros.append(f"Rede CIDR inválida: '{rede}'.")
    if not validar_ip(gateway):
        erros.append(f"Gateway IP inválido: '{gateway}'.")
    elif validar_cidr(rede) and not ip_na_rede(gateway, rede):
        erros.append(f"Gateway {gateway} não pertence à rede {rede}.")

    if erros:
        for e in erros:
            print_erro(e)
        aguardar_enter()
        return

    vlan = {"id": vlan_id, "nome": nome, "rede": rede, "gateway": gateway}
    ok, msg = db.adicionar_vlan(vlan)

    if ok:
        print_ok(f"VLAN {vlan_id} ({nome}) cadastrada.")
        aplicar_agora = input_campo("Aplicar agora no sistema? (s/n)", "s")
        if aplicar_agora.lower() == "s":
            trunk = config.get("trunk_interface", "")
            print()
            ok2, msg2 = vlan_mod.criar_subinterface(trunk, vlan_id, gateway, rede)
            if ok2:
                print_ok(f"Subinterface {trunk}.{vlan_id} criada.")
            else:
                print_erro(f"Erro ao criar subinterface: {msg2}")
    else:
        print_erro(f"Erro ao cadastrar: {msg}")

    aguardar_enter()


def _aplicar_vlans(config: dict):
    cabecalho("Aplicar VLANs")
    print()
    resultados = vlan_mod.aplicar_todas(config)
    if not resultados:
        print_info("Nenhuma VLAN para aplicar.")
    else:
        exibir_resultados(resultados)
        ok_n, err_n = resumo_resultados(resultados)
        print()
        if err_n == 0:
            print_ok(f"Todas as {ok_n} VLANs aplicadas com sucesso.")
        else:
            print_aviso(f"{ok_n} OK, {err_n} com erro.")
    aguardar_enter()


def _remover_vlan_menu(config: dict):
    cabecalho("Remover VLAN")
    vlans = config.get("vlans", [])
    if not vlans:
        print_info("Nenhuma VLAN cadastrada.")
        aguardar_enter()
        return

    for v in vlans:
        linha_texto(f"  VLAN {v['id']}  {v['nome'].ljust(15)}  {v['rede']}", C_WHITE)
    linha_vazia()

    id_str = input_campo("ID da VLAN para remover (ou [V] para cancelar)")
    if id_str.upper() == "V" or not id_str:
        return
    if not id_str.isdigit():
        print_erro("ID inválido.")
        aguardar_enter()
        return

    vlan_id = int(id_str)
    trunk   = config.get("trunk_interface", "")

    print()
    print_info(f"Removendo subinterface {trunk}.{vlan_id} do sistema...")
    ok_s, msg_s = vlan_mod.remover_subinterface(trunk, vlan_id)
    if ok_s:
        print_ok(f"Subinterface {trunk}.{vlan_id} removida.")
    else:
        print_aviso(f"Subinterface: {msg_s}")

    ok_db, msg_db = db.remover_vlan(vlan_id)
    if ok_db:
        print_ok(f"VLAN {vlan_id} removida da configuração.")
    else:
        print_erro(f"Erro ao remover da config: {msg_db}")

    aguardar_enter()


def _remover_todas_vlans(config: dict):
    cabecalho("Remover TODAS as VLANs")
    linha_vazia()
    print_aviso("Isso vai remover todas as subinterfaces VLAN do sistema.")
    linha_vazia()
    conf = input_campo("Confirmar? (s/n)", "n")
    if conf.lower() != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return

    print()
    resultados = vlan_mod.remover_todas(config)
    exibir_resultados(resultados)
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU — ROTEAMENTO / NAT
# ══════════════════════════════════════════════════════════════════════════════

def menu_roteamento():
    while True:
        config = db.carregar()
        fw     = rot.status_ip_forward()
        fw_cor = C_OK if fw == "1" else C_ERRO

        cabecalho("Roteamento / NAT")
        linha_texto(f"  ip_forward : {fw}  {'[ON]' if fw == '1' else '[OFF]'}", fw_cor)
        linha_vazia()
        linha_texto("  [1]  Aplicar roteamento completo (NAT + VLANs + ip_forward)", C_WHITE)
        linha_texto("  [2]  Ativar / Desativar ip_forward", C_WHITE)
        linha_texto("  [3]  Limpar tabela nftables (netforge)", C_AVISO)
        linha_texto("  [4]  Ver regras NAT e FORWARD ativas", C_WHITE)
        linha_texto("  [5]  Roteamento direto entre interfaces", C_WHITE)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if   op == "V": return
        elif op == "1": _aplicar_roteamento_completo(config)
        elif op == "2": _toggle_ip_forward(fw)
        elif op == "3": _limpar_nftables()
        elif op == "4": _ver_regras_nat()
        elif op == "5": _menu_roteamento_direto()


def _aplicar_roteamento_completo(config: dict):
    cabecalho("Aplicar Roteamento Completo")
    wan   = config.get("wan_interface", "—")
    trunk = config.get("trunk_interface", "—")
    vlans = config.get("vlans", [])
    linha_texto(f"  WAN  : {wan}", C_DIM)
    linha_texto(f"  Trunk: {trunk}", C_DIM)
    linha_texto(f"  VLANs: {len(vlans)} configurada(s)", C_DIM)
    linha_vazia()

    if not vlans:
        print_aviso("Nenhuma VLAN cadastrada. Cadastre VLANs antes de aplicar o roteamento.")
        aguardar_enter()
        return

    conf = input_campo("Confirmar? (s/n)", "s")
    if conf.lower() != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return

    print()
    resultados = rot.aplicar_roteamento_completo(config)
    exibir_resultados(resultados)
    ok_n, err_n = resumo_resultados(resultados)
    print()
    if err_n == 0:
        print_ok("Roteamento configurado com sucesso.")
    else:
        print_aviso(f"{ok_n} etapas OK, {err_n} com erro.")

    aguardar_enter()


def _toggle_ip_forward(atual: str):
    if atual == "1":
        ok, err = rot.desativar_ip_forward()
        msg = "ip_forward DESATIVADO" if ok else f"Erro: {err}"
    else:
        ok, err = rot.ativar_ip_forward()
        msg = "ip_forward ATIVADO" if ok else f"Erro: {err}"

    print_ok(msg) if ok else print_erro(msg)
    aguardar_enter()


def _limpar_nftables():
    cabecalho("Limpar Tabela nftables")
    print_aviso("Isso remove TODAS as regras NAT e FORWARD da tabela netforge.")
    conf = input_campo("Confirmar? (s/n)", "n")
    if conf.lower() != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return
    rot.limpar_tabela()
    print_ok("Tabela netforge removida.")
    aguardar_enter()


def _ver_regras_nat():
    cabecalho("Regras NAT e FORWARD Ativas")

    # NAT
    linha_texto("  -- NAT (MASQUERADE) ------------------------------------", C_NEON)
    regras = rot.listar_regras_nat()
    if regras:
        for r in regras:
            linha_texto(f"  {r}", C_OK)
    else:
        linha_texto("  Sem regras NAT ativas.", C_DIM)

    linha_vazia()

    # FORWARD
    linha_texto("  -- FORWARD ---------------------------------------------", C_NEON)
    forwards = rot.listar_forwards()
    if forwards:
        for r in forwards:
            linha_texto(f"  {r}", C_OK)
    else:
        linha_texto("  Sem regras FORWARD ativas.", C_DIM)

    linha_vazia()

    # Rotas
    linha_texto("  -- Rotas -----------------------------------------------", C_NEON)
    for r in rot.listar_rotas()[:10]:
        linha_texto(f"  {r}", C_DIM)

    linha_vazia()
    fundo()
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU — ROTEAMENTO DIRETO ENTRE INTERFACES (sem VLAN)
# ══════════════════════════════════════════════════════════════════════════════

def _menu_roteamento_direto():
    """
    Permite rotear entre duas interfaces físicas quaisquer sem precisar
    de VLANs. Ex: enp0s8 (rede interna) ↔ enp0s9 (outra rede interna).

    Fluxo:
      1. Lista interfaces disponíveis numeradas
      2. Usuário escolhe origem e destino
      3. Pergunta se o destino é WAN (para aplicar MASQUERADE + NAT)
      4. Aplica ip_forward + FORWARD bidirecional + MASQUERADE se WAN
    """
    while True:
        cabecalho("Roteamento direto entre interfaces")

        ifaces = listar_interfaces_sistema()
        # Remove subinterfaces VLAN da lista (têm ponto no nome)
        ifaces = [i for i in ifaces if "." not in i]

        if len(ifaces) < 2:
            print_erro("Menos de 2 interfaces físicas disponíveis.")
            aguardar_enter()
            return

        # Lista interfaces com IP atual para facilitar identificação
        linha_texto("  #   INTERFACE    IP", C_DIM)
        separador()
        infos = {i["nome"]: i for i in _listar_ifaces_com_info()}
        for idx, nome in enumerate(ifaces):
            info = infos.get(nome, {})
            ip_atual = info.get("ip", "—")
            estado   = info.get("estado", "?")
            cor      = C_OK if estado == "UP" else C_DIM
            linha_texto(f"  [{idx}]  {nome.ljust(12)} {ip_atual}", cor)

        linha_vazia()

        # Mostra regras já ativas resumidas
        forwards = rot.listar_forwards()
        if forwards:
            linha_texto("  -- FORWARD já ativas --------------------------------", C_NEON)
            for r in forwards[:4]:
                linha_texto(f"  {r}", C_DIM)
            linha_vazia()

        linha_texto("  [A]  Adicionar rota entre interfaces", C_WHITE)
        linha_texto("  [L]  Limpar todas as rotas (tabela netforge)", C_AVISO)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if   op == "V": return
        elif op == "A": _adicionar_rota_direta(ifaces, infos)
        elif op == "L": _confirmar_limpar_netforge()


def _adicionar_rota_direta(ifaces: list[str], infos: dict):
    """
    Coleta LAN e WAN explicitamente e aplica FORWARD + MASQUERADE.

    Pergunta separado:
      - Qual é a interface LAN (onde estão os clientes/Windows)
      - Qual é a interface WAN (saída para internet)
    Assim não depende de o usuário saber o conceito de origem/destino.
    """
    cabecalho("Adicionar rota direta")

    linha_texto("  Interfaces disponíveis:", C_DIM)
    for idx, nome in enumerate(ifaces):
        ip_atual = infos.get(nome, {}).get("ip", "—")
        linha_texto(f"  [{idx}]  {nome.ljust(12)} {ip_atual}", C_WHITE)
    linha_vazia()

    linha_texto("  LAN = onde estao os PCs / Windows", C_DIM)
    linha_texto("  WAN = cabo que vem da internet / roteador", C_DIM)
    linha_vazia()

    lan_str = input_campo("Número da interface LAN (clientes)")
    wan_str = input_campo("Número da interface WAN (internet)")

    if not lan_str.isdigit() or not wan_str.isdigit():
        print_erro("Entrada inválida — digite o número da interface.")
        aguardar_enter()
        return

    idx_lan = int(lan_str)
    idx_wan = int(wan_str)

    if idx_lan == idx_wan:
        print_erro("LAN e WAN não podem ser a mesma interface.")
        aguardar_enter()
        return

    if idx_lan >= len(ifaces) or idx_wan >= len(ifaces):
        print_erro("Número fora do intervalo.")
        aguardar_enter()
        return

    lan = ifaces[idx_lan]
    wan = ifaces[idx_wan]

    linha_vazia()
    linha_texto(f"  LAN (clientes) : {lan}", C_OK)
    linha_texto(f"  WAN (internet) : {wan}", C_OK)
    linha_vazia()
    linha_texto("  Vai aplicar: MASQUERADE + FORWARD LAN→WAN", C_DIM)
    linha_vazia()

    conf = input_campo("Confirmar? (s/n)", "s").strip().lower()
    if conf != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return

    print()

    # 1. ip_forward
    ok_fw, err_fw = rot.ativar_ip_forward()
    print_ok("ip_forward ativado") if ok_fw else print_aviso(f"ip_forward: {err_fw}")

    # 2. Limpa tabela netforge completamente antes de aplicar (evita duplicatas)
    print_info("Limpando regras antigas...")
    rot.limpar_tabela()
    ok_tab, err_tab = rot.criar_tabela()
    if ok_tab:
        print_ok("Tabela netforge recriada do zero")
    else:
        print_erro(f"Erro ao criar tabela: {err_tab}")
        aguardar_enter()
        return

    # 3. MASQUERADE na WAN
    ok_nat, err_nat = rot.aplicar_masquerade(wan)
    if ok_nat:
        print_ok(f"MASQUERADE em {wan}")
    else:
        print_aviso(f"MASQUERADE: {err_nat}")

    # 4. FORWARD LAN → WAN com retorno stateful
    ok_fwd, err_fwd = rot.aplicar_forward_interface_wan(lan, wan)
    if ok_fwd:
        print_ok(f"FORWARD: {lan} → {wan} (retorno stateful)")
    else:
        print_erro(f"Erro no FORWARD: {err_fwd}")

    # 5. Mostra como ficou
    linha_vazia()
    linha_texto("  -- Regras aplicadas ------------------------------------", C_NEON)
    for r in rot.listar_regras_nat():
        linha_texto(f"  NAT    : {r}", C_OK)
    for r in rot.listar_forwards():
        linha_texto(f"  FORWARD: {r}", C_OK)
    linha_vazia()

    if ok_fwd and ok_nat:
        print_ok(f"Pronto! {lan} → {wan} com NAT. Teste: ping 8.8.8.8 no cliente.")
    else:
        print_aviso("Aplicado com avisos — veja erros acima.")

    aguardar_enter()


def _confirmar_limpar_netforge():
    """Confirma e limpa toda a tabela netforge."""
    cabecalho("Limpar tabela netforge")
    print_aviso("Remove TODAS as regras de roteamento direto e NAT.")
    conf = input_campo("Confirmar? (s/n)", "n")
    if conf.lower() != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return
    rot.limpar_tabela()
    print_ok("Tabela netforge removida — sem regras ativas.")
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU — DHCP RELAY
# ══════════════════════════════════════════════════════════════════════════════

def menu_relay():
    while True:
        config  = db.carregar()
        status  = relay_mod.status_relay()
        trunk   = config.get("trunk_interface", "")
        vlans   = config.get("vlans", [])
        dhcp_sv = config.get("dhcp_server", "") or "—"

        cabecalho("DHCP Relay")

        rel_cor = C_OK if status["ativo"] else C_ERRO
        linha_texto(f"  Status     : {'ATIVO' if status['ativo'] else 'PARADO'}", rel_cor)
        if status["pid"]:
            linha_texto(f"  PID        : {status['pid']}", C_DIM)
        if status["interfaces"]:
            linha_texto(f"  Interfaces : {', '.join(status['interfaces'])}", C_DIM)
        if status["servidor"]:
            linha_texto(f"  DHCP Srv   : {status['servidor']}", C_DIM)
        linha_texto(f"  Config Srv : {dhcp_sv}", C_DIM)
        linha_vazia()

        if not relay_mod.dhcrelay_disponivel():
            print_aviso(f"dhcrelay não instalado. Use: {relay_mod.instrucoes_instalacao()}")
            linha_vazia()

        linha_texto("  [1]  Iniciar relay", C_WHITE)
        linha_texto("  [2]  Parar relay", C_AVISO)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if   op == "V": return
        elif op == "1": _iniciar_relay(config, trunk, vlans)
        elif op == "2": _parar_relay()


def _iniciar_relay(config: dict, trunk: str, vlans: list):
    cabecalho("Iniciar DHCP Relay")

    dhcp_sv = config.get("dhcp_server", "")
    if not dhcp_sv:
        dhcp_sv = input_campo("IP do servidor DHCP (Windows Server)")
        if not validar_ip(dhcp_sv):
            print_erro("IP inválido.")
            aguardar_enter()
            return
        db.atualizar_global("dhcp_server", dhcp_sv)

    if not vlans:
        print_erro("Nenhuma VLAN configurada. Cadastre VLANs primeiro.")
        aguardar_enter()
        return

    ifaces_vlan = [f"{trunk}.{v['id']}" for v in vlans]

    print()
    print_info(f"Iniciando relay para {dhcp_sv}...")
    print_info(f"Interfaces: {', '.join(ifaces_vlan)}")
    print()

    ok, msg = relay_mod.iniciar_relay(dhcp_sv, ifaces_vlan)
    if ok:
        print_ok(f"Relay iniciado. {msg}")
    else:
        print_erro(f"Erro: {msg}")

    aguardar_enter()


def _parar_relay():
    ok, msg = relay_mod.parar_relay()
    print_ok(msg) if ok else print_erro(msg)
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU — CONFIGURAÇÕES GERAIS
# ══════════════════════════════════════════════════════════════════════════════

def menu_configuracoes():
    while True:
        config = db.carregar()
        cabecalho("Configurações Gerais")

        linha_texto(f"  Trunk interface : {config.get('trunk_interface', '—')}", C_DIM)
        linha_texto(f"  WAN interface   : {config.get('wan_interface', '—')}", C_DIM)
        linha_texto(f"  DHCP Server     : {config.get('dhcp_server', '—') or '—'}", C_DIM)
        linha_vazia()
        linha_texto("  [1]  Alterar interface Trunk", C_WHITE)
        linha_texto("  [2]  Alterar interface WAN", C_WHITE)
        linha_texto("  [3]  Alterar IP do servidor DHCP", C_WHITE)
        linha_texto("  [V]  Voltar", C_DIM)
        linha_vazia()
        fundo()

        op = ler_opcao()
        if op == "V":
            return

        ifaces = listar_interfaces_sistema()

        if op in ("1", "2"):
            chave  = "trunk_interface" if op == "1" else "wan_interface"
            label  = "Trunk" if op == "1" else "WAN"
            atual  = config.get(chave, "")
            linha_vazia()
            linha_texto("  Interfaces disponíveis: " + ", ".join(ifaces), C_DIM)
            nova = input_campo(f"Nova interface {label}", atual)
            if nova not in ifaces and nova:
                print_aviso(f"Interface '{nova}' não encontrada no sistema. Salvo mesmo assim.")
            if nova:
                db.atualizar_global(chave, nova)
                print_ok(f"{label} alterada para '{nova}'.")
            aguardar_enter()

        elif op == "3":
            atual = config.get("dhcp_server", "")
            novo  = input_campo("IP do servidor DHCP", atual)
            if novo and not validar_ip(novo):
                print_erro("IP inválido.")
            elif novo:
                db.atualizar_global("dhcp_server", novo)
                print_ok(f"DHCP Server alterado para '{novo}'.")
            aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU — STATUS COMPLETO
# ══════════════════════════════════════════════════════════════════════════════

def menu_status():
    config = db.carregar()
    trunk  = config.get("trunk_interface", "—")
    cabecalho("Status Completo da Rede")

    # Interfaces físicas
    linha_texto("  -- Interfaces físicas ---------------------------------", C_NEON)
    for iface in _listar_ifaces_com_info():
        cor = C_OK if iface["estado"] == "UP" else C_ERRO
        linha_texto(
            f"  {iface['nome'].ljust(12)} {iface['ip'].ljust(17)} /{iface['mask'].ljust(4)} {iface['estado']}",
            cor,
        )

    linha_vazia()

    # Subinterfaces VLAN ativas
    linha_texto("  -- Subinterfaces VLAN ---------------------------------", C_NEON)
    subs = vlan_mod.listar_subinterfaces_ativas(trunk)
    if subs:
        for s in subs:
            cor = C_OK if s["estado"] == "UP" else C_ERRO
            linha_texto(
                f"  {s['nome'].ljust(14)} {s['ip'].ljust(20)} {s['estado']}", cor
            )
    else:
        linha_texto("  Nenhuma subinterface VLAN ativa.", C_DIM)

    linha_vazia()

    # ip_forward
    linha_texto("  -- ip_forward -----------------------------------------", C_NEON)
    fw     = rot.status_ip_forward()
    fw_cor = C_OK if fw == "1" else C_ERRO
    linha_texto(
        f"  ip_forward = {fw}  {'(roteamento ativo)' if fw == '1' else '(roteamento desativado)'}",
        fw_cor,
    )

    linha_vazia()

    # NAT
    linha_texto("  -- NAT (nftables / netforge) --------------------------", C_NEON)
    regras_nat = rot.listar_regras_nat()
    if regras_nat:
        for r in regras_nat:
            linha_texto(f"  {r}", C_OK)
    else:
        linha_texto("  Sem regras NAT ativas.", C_DIM)

    linha_vazia()

    # FORWARD direto
    linha_texto("  -- FORWARD direto (netforge) --------------------------", C_NEON)
    forwards = rot.listar_forwards()
    if forwards:
        for r in forwards[:6]:
            linha_texto(f"  {r}", C_OK)
    else:
        linha_texto("  Sem regras FORWARD ativas.", C_DIM)

    linha_vazia()

    # DHCP Relay
    linha_texto("  -- DHCP Relay -----------------------------------------", C_NEON)
    rel = relay_mod.status_relay()
    rel_cor = C_OK if rel["ativo"] else C_ERRO
    linha_texto(f"  Status : {'ATIVO' if rel['ativo'] else 'PARADO'}", rel_cor)
    if rel["pid"]:
        linha_texto(f"  PID    : {rel['pid']}", C_DIM)
    if rel["servidor"]:
        linha_texto(f"  Srv    : {rel['servidor']}", C_DIM)

    linha_vazia()

    # DNS
    linha_texto("  -- DNS ------------------------------------------------", C_NEON)
    ok, dns_out, _ = rodar("cat /etc/resolv.conf 2>/dev/null", silencioso=True)
    if ok:
        for l in dns_out.splitlines():
            if l.startswith("nameserver"):
                linha_texto(f"  {l}", C_DIM)

    linha_vazia()

    # Rotas
    linha_texto("  -- Rotas ----------------------------------------------", C_NEON)
    for r in rot.listar_rotas()[:8]:
        linha_texto(f"  {r}", C_DIM)

    linha_vazia()
    fundo()
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════════════════

def _listar_ifaces_com_info() -> list[dict]:
    """Retorna lista de interfaces físicas com IP, máscara, estado e MAC."""
    resultado = []
    ok, saida, _ = rodar("ip -o addr show", silencioso=True)
    if not ok:
        return resultado

    vistas: set[str] = set()

    for linha in saida.splitlines():
        partes = linha.split()
        if len(partes) < 4:
            continue
        nome = partes[1]
        if nome == "lo" or nome in vistas:
            continue
        if partes[2] != "inet":
            continue
        # Ignora subinterfaces VLAN (têm ponto no nome: enp0s9.10)
        if "." in nome:
            continue

        cidr = partes[3]
        ip   = cidr.split("/")[0]
        mask = cidr.split("/")[1] if "/" in cidr else "24"
        vistas.add(nome)

        ok2, s2, _ = rodar(["ip", "link", "show", nome], silencioso=True)
        estado = "UP" if ("UP" in s2 and "LOWER_UP" in s2) else "DOWN"
        mac_m  = re.search(r"link/ether ([0-9a-f:]+)", s2)
        mac    = mac_m.group(1) if mac_m else "—"

        resultado.append({
            "nome": nome, "ip": ip, "mask": mask,
            "estado": estado, "mac": mac,
        })

    # Interfaces sem IP
    ok3, s3, _ = rodar(["ip", "link", "show"], silencioso=True)
    for m in re.finditer(r"\d+: (\w+):", s3):
        nome = m.group(1)
        if nome == "lo" or nome in vistas or "." in nome:
            continue
        ok4, s4, _ = rodar(["ip", "link", "show", nome], silencioso=True)
        estado = "UP" if "UP" in s4 else "DOWN"
        mac_m  = re.search(r"link/ether ([0-9a-f:]+)", s4)
        mac    = mac_m.group(1) if mac_m else "—"
        resultado.append({
            "nome": nome, "ip": "—", "mask": "—",
            "estado": estado, "mac": mac,
        })
        vistas.add(nome)

    return resultado