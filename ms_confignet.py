#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  MOONSHIELD · NETFORGE  v1.0                                ║
║  Configuração de rede e roteamento para o sensor Linux       ║
║                                                              ║
║  Uso: sudo python3 ms_netforge.py                            ║
╚══════════════════════════════════════════════════════════════╝

Funcionalidades:
  [1] Configurar interfaces (IP estático ou DHCP)
  [2] Configurar roteamento / NAT (compartilhar internet)
  [3] Ativar / desativar ip_forward
  [4] Ver status completo da rede
  [V] Voltar / Sair
"""

import os
import sys
import subprocess
import re
import time

# ══════════════════════════════════════════════════════════════════════════════
# CORES E ESTILO
# ══════════════════════════════════════════════════════════════════════════════

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_DIM    = "\033[2m"
C_OK     = "\033[92m"
C_ERRO   = "\033[91m"
C_AVISO  = "\033[93m"
C_TITULO = "\033[96m"
C_WHITE  = "\033[97m"
C_NEON   = "\033[92m\033[2m"
C_BORDA  = "\033[90m"

LARGURA = 62


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS DE INTERFACE TUI
# ══════════════════════════════════════════════════════════════════════════════

def limpar():
    os.system("clear")


def topo():
    print(C_BORDA + "  +" + "=" * LARGURA + "+" + C_RESET)


def fundo():
    print(C_BORDA + "  +" + "=" * LARGURA + "+" + C_RESET)


def separador():
    print(C_BORDA + "  +" + "-" * LARGURA + "+" + C_RESET)


def linha_vazia():
    print(C_BORDA + "  |" + " " * LARGURA + "|" + C_RESET)


def linha_texto(texto, cor=C_WHITE, alinhamento="esquerda"):
    if alinhamento == "centro":
        pad = (LARGURA - len(texto)) // 2
        conteudo = " " * pad + texto
    else:
        conteudo = " " + texto
    conteudo = conteudo[:LARGURA].ljust(LARGURA)
    print(C_BORDA + "  |" + cor + conteudo + C_RESET + C_BORDA + "|" + C_RESET)


def cabecalho():
    limpar()
    topo()
    linha_texto("MOONSHIELD  ·  NETFORGE  v1.0", C_TITULO, "centro")
    linha_texto("Configuracao de rede e roteamento", C_DIM, "centro")
    separador()


def aguardar_enter():
    print()
    print(C_DIM + "  Pressione ENTER para continuar..." + C_RESET, end="")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


def input_campo(label, padrao=""):
    hint = f" [{padrao}]" if padrao else ""
    print(C_AVISO + f"  > {label}{hint}: " + C_WHITE, end="")
    try:
        val = input().strip()
        return val if val else padrao
    except (KeyboardInterrupt, EOFError):
        return padrao


def print_ok(msg):
    print(C_OK + f"  [OK] {msg}" + C_RESET)


def print_erro(msg):
    print(C_ERRO + f"  [!!] {msg}" + C_RESET)


def print_aviso(msg):
    print(C_AVISO + f"  [!] {msg}" + C_RESET)


def print_info(msg):
    print(C_DIM + f"  [ ] {msg}" + C_RESET)


def rodar(cmd, silencioso=False):
    """Executa comando e retorna (ok, stdout, stderr)."""
    try:
        r = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)


# ══════════════════════════════════════════════════════════════════════════════
# LIMPEZA DE CONFIGURAÇÃO DE INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

def limpar_interface(nome: str):
    """
    Remove TODOS os IPs, rotas e processos DHCP associados à interface.
    Deve ser chamado antes de aplicar qualquer nova configuração.
    """
    print_info(f"Limpando configuracao atual de {nome}...")

    # Mata processos dhclient / udhcpc em execução para esta interface
    rodar(f"pkill -f 'dhclient.*{nome}'", silencioso=True)
    rodar(f"pkill -f 'udhcpc.*{nome}'", silencioso=True)
    rodar(f"dhclient -r {nome}", silencioso=True)

    # Remove todas as rotas que passam por esta interface
    ok, rotas, _ = rodar(f"ip route show dev {nome}", silencioso=True)
    if ok and rotas:
        for rota in rotas.splitlines():
            rota = rota.strip()
            if rota:
                rodar(f"ip route del {rota.split()[0]} dev {nome}", silencioso=True)

    # Remove rota default se tiver esta interface
    ok2, default_r, _ = rodar("ip route show default", silencioso=True)
    if ok2 and nome in default_r:
        rodar("ip route del default", silencioso=True)

    # Remove todos os IPs da interface (flush)
    rodar(f"ip addr flush dev {nome}", silencioso=True)

    print_ok(f"Interface {nome} limpa")


# ══════════════════════════════════════════════════════════════════════════════
# DETECÇÃO DE INTERFACES
# ══════════════════════════════════════════════════════════════════════════════

def listar_interfaces() -> list[dict]:
    """Retorna lista de interfaces com nome, IP, máscara, estado e MAC."""
    interfaces = []
    try:
        ok, saida, _ = rodar("ip -o addr show", silencioso=True)
        if not ok:
            return []

        vistas = set()
        for linha in saida.splitlines():
            partes = linha.split()
            if len(partes) < 4:
                continue
            nome = partes[1]
            if nome == "lo" or nome in vistas:
                continue

            if partes[2] != "inet":
                continue

            cidr  = partes[3]
            ip    = cidr.split("/")[0]
            mask  = cidr.split("/")[1] if "/" in cidr else "24"
            vistas.add(nome)

            ok2, s2, _ = rodar(f"ip link show {nome}", silencioso=True)
            estado = "UP" if "UP" in s2 and "LOWER_UP" in s2 else "DOWN"
            mac_m  = re.search(r"link/ether ([0-9a-f:]+)", s2)
            mac    = mac_m.group(1) if mac_m else "—"

            interfaces.append({
                "nome":   nome,
                "ip":     ip,
                "mask":   mask,
                "estado": estado,
                "mac":    mac,
                "cidr":   cidr,
            })

        # Adiciona interfaces que existem mas não têm IP
        ok3, s3, _ = rodar("ip link show", silencioso=True)
        for m in re.finditer(r"\d+: (\w+):", s3):
            nome = m.group(1)
            if nome == "lo" or nome in vistas:
                continue
            ok4, s4, _ = rodar(f"ip link show {nome}", silencioso=True)
            estado = "UP" if "UP" in s4 else "DOWN"
            mac_m  = re.search(r"link/ether ([0-9a-f:]+)", s4)
            mac    = mac_m.group(1) if mac_m else "—"
            interfaces.append({
                "nome":   nome,
                "ip":     "—",
                "mask":   "—",
                "estado": estado,
                "mac":    mac,
                "cidr":   "",
            })
            vistas.add(nome)

    except Exception as e:
        print_erro(f"Erro ao listar interfaces: {e}")
    return interfaces


def exibir_interfaces(interfaces: list[dict]):
    """Exibe tabela de interfaces."""
    linha_texto("  #   INTERFACE    IP               MASCARA  ESTADO", C_DIM)
    separador()
    for i, iface in enumerate(interfaces):
        cor  = C_OK if iface["estado"] == "UP" else C_ERRO
        num  = f"[{i+1}]"
        nome = iface["nome"].ljust(10)
        ip   = iface["ip"].ljust(16)
        mask = f"/{iface['mask']}".ljust(8)
        est  = iface["estado"]
        linha_texto(f"  {num}  {nome} {ip} {mask} {est}", cor)


def detectar_gateway_padrao() -> str | None:
    """Detecta o gateway padrão atual."""
    ok, saida, _ = rodar("ip route show default", silencioso=True)
    if ok and saida:
        m = re.search(r"default via (\S+)", saida)
        if m:
            return m.group(1)
    return None


# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURAÇÃO DE INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

def configurar_interface(interfaces: list[dict]):
    cabecalho()
    linha_texto("  CONFIGURAR INTERFACE", C_TITULO)
    linha_vazia()
    exibir_interfaces(interfaces)
    linha_vazia()
    fundo()

    escolha = input_campo("Numero da interface (ou nome)")
    if not escolha:
        return

    iface = None
    if escolha.isdigit():
        idx = int(escolha) - 1
        if 0 <= idx < len(interfaces):
            iface = interfaces[idx]
    else:
        iface = next((i for i in interfaces if i["nome"] == escolha), None)

    if not iface:
        print_erro("Interface nao encontrada.")
        aguardar_enter()
        return

    cabecalho()
    linha_texto(f"  CONFIGURAR: {iface['nome']}", C_TITULO)
    linha_vazia()
    linha_texto(f"  IP atual    : {iface['ip']}", C_DIM)
    linha_texto(f"  Mascara     : /{iface['mask']}", C_DIM)
    linha_texto(f"  Estado      : {iface['estado']}", C_DIM)
    linha_texto(f"  MAC         : {iface['mac']}", C_DIM)
    linha_vazia()
    linha_texto("  [1]  IP estatico", C_WHITE)
    linha_texto("  [2]  DHCP", C_WHITE)
    linha_texto("  [3]  Apenas ativar interface (sem IP)", C_WHITE)
    linha_texto("  [4]  Desativar interface", C_AVISO)
    linha_vazia()
    fundo()

    modo = input_campo("Modo")

    if modo == "1":
        _configurar_estatico(iface)
    elif modo == "2":
        _configurar_dhcp(iface)
    elif modo == "3":
        _ativar_interface(iface["nome"])
    elif modo == "4":
        _desativar_interface(iface["nome"])
    else:
        print_info("Cancelado.")
        aguardar_enter()


def _configurar_estatico(iface: dict):
    cabecalho()
    linha_texto(f"  IP ESTATICO — {iface['nome']}", C_TITULO)
    linha_vazia()

    ip_atual = iface["ip"] if iface["ip"] != "—" else ""
    ip       = input_campo("IP", ip_atual)
    mascara  = input_campo("Mascara de rede (bits)", iface["mask"] if iface["mask"] != "—" else "24")
    gateway  = input_campo("Gateway (vazio = sem gateway)", detectar_gateway_padrao() or "")

    if not ip:
        print_erro("IP obrigatorio.")
        aguardar_enter()
        return

    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        print_erro("IP invalido.")
        aguardar_enter()
        return

    print()

    # ── LIMPA a configuração atual da interface antes de aplicar ──
    limpar_interface(iface["nome"])

    print_info(f"Aplicando nova configuracao em {iface['nome']}...")

    # Ativa a interface
    ok, _, err = rodar(f"ip link set {iface['nome']} up")
    if not ok:
        print_erro(f"Erro ao ativar interface: {err}")
        aguardar_enter()
        return

    # Aplica IP
    ok, _, err = rodar(f"ip addr add {ip}/{mascara} dev {iface['nome']}")
    if not ok:
        print_erro(f"Erro ao aplicar IP: {err}")
        aguardar_enter()
        return

    print_ok(f"IP {ip}/{mascara} aplicado em {iface['nome']}")

    # Gateway
    if gateway:
        rodar("ip route del default", silencioso=True)
        ok2, _, err2 = rodar(f"ip route add default via {gateway}")
        if ok2:
            print_ok(f"Gateway {gateway} configurado")
        else:
            print_aviso(f"Gateway nao aplicado: {err2}")

    aguardar_enter()


def _configurar_dhcp(iface: dict):
    cabecalho()
    linha_texto(f"  DHCP — {iface['nome']}", C_TITULO)
    linha_vazia()
    print_info(f"Solicitando IP via DHCP em {iface['nome']}...")
    print()

    # ── LIMPA a configuração atual da interface antes de pedir DHCP ──
    limpar_interface(iface["nome"])

    # Ativa a interface
    rodar(f"ip link set {iface['nome']} up", silencioso=True)

    # Tenta dhclient
    ok, _, _ = rodar("which dhclient", silencioso=True)
    if ok:
        print_info("Usando dhclient...")
        ok2, saida, err = rodar(f"dhclient {iface['nome']}", silencioso=True)
        if ok2:
            print_ok(f"DHCP aplicado em {iface['nome']}")
        else:
            print_erro(f"dhclient falhou: {err[:80]}")
    else:
        ok3, _, _ = rodar("which udhcpc", silencioso=True)
        if ok3:
            print_info("Usando udhcpc...")
            ok4, _, err4 = rodar(f"udhcpc -i {iface['nome']} -q")
            if ok4:
                print_ok(f"DHCP aplicado em {iface['nome']}")
            else:
                print_erro(f"udhcpc falhou: {err4[:80]}")
        else:
            print_erro("Nenhum cliente DHCP encontrado (dhclient ou udhcpc).")

    aguardar_enter()


def _ativar_interface(nome: str):
    ok, _, err = rodar(f"ip link set {nome} up")
    if ok:
        print_ok(f"Interface {nome} ativada")
    else:
        print_erro(f"Erro: {err}")
    aguardar_enter()


def _desativar_interface(nome: str):
    # ── LIMPA antes de desativar ──
    limpar_interface(nome)
    ok, _, err = rodar(f"ip link set {nome} down")
    if ok:
        print_ok(f"Interface {nome} desativada")
    else:
        print_erro(f"Erro: {err}")
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# ROTEAMENTO E NAT
# ══════════════════════════════════════════════════════════════════════════════

def configurar_roteamento(interfaces: list[dict]):
    cabecalho()
    linha_texto("  ROTEAMENTO / NAT", C_TITULO)
    linha_vazia()
    linha_texto("  Compartilha a internet de uma interface", C_DIM)
    linha_texto("  para as outras — Gateway / Router mode.", C_DIM)
    linha_vazia()
    exibir_interfaces(interfaces)
    linha_vazia()
    fundo()

    if len(interfaces) < 2:
        print_erro("Necessario ao menos 2 interfaces.")
        aguardar_enter()
        return

    wan_input = input_campo("Interface WAN (internet) — numero ou nome")
    lan_input = input_campo("Interface LAN (rede interna) — numero ou nome (vazio = todas as outras)")

    iface_wan = _resolver_interface(wan_input, interfaces)
    if not iface_wan:
        print_erro("Interface WAN nao encontrada.")
        aguardar_enter()
        return

    if lan_input.strip():
        iface_lan = _resolver_interface(lan_input, interfaces)
        if not iface_lan:
            print_erro("Interface LAN nao encontrada.")
            aguardar_enter()
            return
        lans = [iface_lan["nome"]]
    else:
        lans = [i["nome"] for i in interfaces if i["nome"] != iface_wan["nome"]]

    cabecalho()
    linha_texto("  CONFIRMAR CONFIGURACAO", C_TITULO)
    linha_vazia()
    linha_texto(f"  WAN (internet): {iface_wan['nome']}  {iface_wan['ip']}", C_OK)
    for lan in lans:
        linha_texto(f"  LAN (interna) : {lan}", C_WHITE)
    linha_vazia()
    linha_texto("  Isso vai:", C_DIM)
    linha_texto("  1. Limpar regras NAT/FORWARD anteriores", C_DIM)
    linha_texto("  2. Ativar ip_forward no kernel", C_DIM)
    linha_texto("  3. Adicionar regras nftables de MASQUERADE", C_DIM)
    linha_texto("  4. Adicionar regras de FORWARD entre WAN e LAN", C_DIM)
    linha_vazia()

    confirma = input_campo("Confirmar? (s/n)", "s")
    if confirma.lower() != "s":
        print_info("Cancelado.")
        aguardar_enter()
        return

    print()
    _aplicar_nat(iface_wan["nome"], lans)
    aguardar_enter()


def _limpar_nat_anterior():
    """Remove tabelas moonshield (ip e inet) para evitar duplicação de regras."""
    print_info("Limpando regras NAT anteriores...")
    # Tenta remover nas duas famílias (ip e inet) para garantir limpeza total
    rodar("nft delete table ip moonshield 2>/dev/null", silencioso=True)
    rodar("nft delete table inet moonshield 2>/dev/null", silencioso=True)
    print_ok("Regras NAT anteriores removidas")


def _aplicar_nat(wan: str, lans: list[str]):
    erros = 0

    # 1. Limpa regras NAT antigas para evitar duplicação
    _limpar_nat_anterior()

    # 2. ip_forward
    ok, _, _ = rodar("sysctl -w net.ipv4.ip_forward=1")
    if ok:
        print_ok("ip_forward ativado")
        _persistir_sysctl("net.ipv4.ip_forward", "1")
    else:
        print_erro("Falha ao ativar ip_forward")
        erros += 1

    # 3. Cria tabela e chains NAT do zero — verifica cada etapa
    ok_nat = _garantir_tabela_nat()
    if not ok_nat:
        print_erro("Falha ao criar tabela/chains nftables. Abortando NAT.")
        aguardar_enter()
        return

    # 4. MASQUERADE na WAN
    # Família "ip" (IPv4) — hook nat só funciona com "ip" em kernels sem suporte inet nat
    ok2, _, err2 = rodar(
        f'nft add rule ip moonshield ms_nat_post oifname "{wan}" masquerade'
    )
    if ok2:
        print_ok(f"MASQUERADE ativado em {wan}")
    else:
        print_erro(f"Falha MASQUERADE: {err2[:80]}")
        erros += 1

    # 5. FORWARD para cada LAN
    for lan in lans:
        ok_fwd1, _, err_fwd1 = rodar(
            f'nft add rule ip moonshield ms_forward_rt iifname "{lan}" oifname "{wan}" accept'
        )
        ok_fwd2, _, err_fwd2 = rodar(
            f'nft add rule ip moonshield ms_forward_rt iifname "{wan}" oifname "{lan}" ct state established,related accept'
        )
        if ok_fwd1 and ok_fwd2:
            print_ok(f"FORWARD configurado: {lan} <-> {wan}")
        else:
            print_erro(f"Falha FORWARD {lan}: {(err_fwd1 or err_fwd2)[:80]}")
            erros += 1

    if erros == 0:
        print()
        print_ok("Roteamento/NAT configurado com sucesso!")
        print()
        print_info("Para testar, tente pingar 8.8.8.8 em um cliente na LAN.")
    else:
        print()
        print_erro(f"{erros} erro(s) encontrado(s).")


def _garantir_tabela_nat() -> bool:
    """
    Cria tabela e chains nftables usando família 'ip' (IPv4).
    O hook 'nat' NÃO é suportado pela família 'inet' em kernels mais antigos —
    usar 'ip' garante compatibilidade.
    Retorna True se tudo foi criado com sucesso, False caso contrário.
    """
    passos = [
        ("tabela ip moonshield",
         "nft add table ip moonshield"),
        ("chain ms_nat_post (NAT postrouting)",
         "nft add chain ip moonshield ms_nat_post { type nat hook postrouting priority 100 ; }"),
        ("chain ms_forward_rt (filter forward)",
         "nft add chain ip moonshield ms_forward_rt { type filter hook forward priority 0 ; policy accept ; }"),
    ]
    for descricao, cmd in passos:
        ok, _, err = rodar(cmd, silencioso=False)
        if not ok:
            print_erro(f"Erro ao criar {descricao}: {err[:80]}")
            return False
        print_ok(f"Criado: {descricao}")
    return True


def _persistir_sysctl(chave: str, valor: str):
    """Salva configuração no /etc/sysctl.d/99-moonshield.conf sem duplicar."""
    try:
        conf = "/etc/sysctl.d/99-moonshield.conf"
        linhas = []
        if os.path.exists(conf):
            with open(conf) as f:
                linhas = f.readlines()

        # Remove linhas antigas com a mesma chave
        linhas = [l for l in linhas if not l.strip().startswith(chave)]

        # Adiciona a nova
        linhas.append(f"{chave} = {valor}\n")

        with open(conf, "w") as f:
            f.writelines(linhas)
    except Exception:
        pass


def _resolver_interface(entrada: str, interfaces: list[dict]) -> dict | None:
    if entrada.isdigit():
        idx = int(entrada) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    return next((i for i in interfaces if i["nome"] == entrada), None)


# ══════════════════════════════════════════════════════════════════════════════
# IP FORWARD
# ══════════════════════════════════════════════════════════════════════════════

def toggle_ip_forward():
    cabecalho()
    linha_texto("  IP FORWARD", C_TITULO)
    linha_vazia()

    ok, val, _ = rodar("sysctl net.ipv4.ip_forward", silencioso=True)
    atual = val.split("=")[-1].strip() if ok and "=" in val else "?"
    cor   = C_OK if atual == "1" else C_ERRO
    linha_texto(f"  Status atual: {atual}", cor)
    linha_vazia()

    if atual == "1":
        linha_texto("  [1]  Desativar ip_forward", C_AVISO)
    else:
        linha_texto("  [1]  Ativar ip_forward", C_WHITE)

    linha_texto("  [V]  Voltar", C_DIM)
    linha_vazia()
    fundo()

    op = input_campo("Opcao").upper()
    if op == "1":
        novo = "0" if atual == "1" else "1"
        ok2, _, err = rodar(f"sysctl -w net.ipv4.ip_forward={novo}")
        if ok2:
            _persistir_sysctl("net.ipv4.ip_forward", novo)
            estado = "ATIVADO" if novo == "1" else "DESATIVADO"
            print_ok(f"ip_forward {estado}")
        else:
            print_erro(f"Erro: {err}")
        aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# STATUS DA REDE
# ══════════════════════════════════════════════════════════════════════════════

def ver_status():
    cabecalho()
    linha_texto("  STATUS DA REDE", C_TITULO)
    linha_vazia()

    # Interfaces
    linha_texto("  -- Interfaces ----------------------------------------", C_NEON)
    interfaces = listar_interfaces()
    for iface in interfaces:
        cor = C_OK if iface["estado"] == "UP" else C_ERRO
        linha_texto(
            f"  {iface['nome'].ljust(10)} {iface['ip'].ljust(16)} /{iface['mask'].ljust(4)} {iface['estado']}",
            cor,
        )

    linha_vazia()

    # Rotas
    linha_texto("  -- Rotas ---------------------------------------------", C_NEON)
    ok, rotas, _ = rodar("ip route show", silencioso=True)
    if ok:
        for linha in rotas.splitlines()[:8]:
            linha_texto(f"  {linha}", C_DIM)

    linha_vazia()

    # ip_forward
    linha_texto("  -- ip_forward ----------------------------------------", C_NEON)
    ok2, val, _ = rodar("sysctl net.ipv4.ip_forward", silencioso=True)
    fw_val = val.split("=")[-1].strip() if ok2 and "=" in val else "?"
    cor2   = C_OK if fw_val == "1" else C_ERRO
    linha_texto(f"  ip_forward = {fw_val}  {'(roteamento ativo)' if fw_val == '1' else '(roteamento desativado)'}", cor2)

    linha_vazia()

    # nftables NAT
    linha_texto("  -- nftables NAT ---------------------------------------", C_NEON)
    ok3, nat_out, _ = rodar(
        "nft list chain ip moonshield ms_nat_post 2>/dev/null", silencioso=True
    )
    if ok3 and nat_out:
        for l in nat_out.splitlines():
            if "masquerade" in l or "snat" in l:
                linha_texto(f"  {l.strip()}", C_OK)
    else:
        linha_texto("  Sem regras NAT ativas", C_DIM)

    linha_vazia()

    # DNS
    linha_texto("  -- DNS -----------------------------------------------", C_NEON)
    ok4, dns_out, _ = rodar("cat /etc/resolv.conf 2>/dev/null", silencioso=True)
    if ok4:
        for l in dns_out.splitlines():
            if l.startswith("nameserver"):
                linha_texto(f"  {l}", C_DIM)

    linha_vazia()
    fundo()
    aguardar_enter()


# ══════════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def menu_principal():
    while True:
        cabecalho()

        interfaces = listar_interfaces()

        linha_texto("  -- Interfaces ativas ----------------------------------", C_NEON)
        for iface in interfaces:
            cor  = C_OK if iface["estado"] == "UP" else C_ERRO
            info = f"  {iface['nome'].ljust(10)} {iface['ip'].ljust(16)} /{iface['mask']}"
            linha_texto(info, cor)

        ok_fw, fw_val, _ = rodar("sysctl net.ipv4.ip_forward", silencioso=True)
        fw = fw_val.split("=")[-1].strip() if ok_fw and "=" in fw_val else "?"
        cor_fw = C_OK if fw == "1" else C_ERRO
        linha_texto(f"  ip_forward: {fw}  {'[roteamento ON]' if fw == '1' else '[roteamento OFF]'}", cor_fw)

        separador()
        linha_texto("  --- Opcoes -------------------------------------------", C_NEON)
        linha_texto("  [1]  >>  Configurar interface (IP / DHCP)", C_WHITE)
        linha_texto("  [2]  >>  Configurar roteamento / NAT (Gateway mode)", C_WHITE)
        linha_texto("  [3]  --  Ativar / Desativar ip_forward", C_WHITE)
        linha_texto("  [4]  --  Ver status completo da rede", C_WHITE)
        linha_vazia()
        linha_texto("  [V]  <<  Sair", C_DIM)
        linha_vazia()
        fundo()

        print(C_AVISO + "  > Opcao: " + C_WHITE, end="")
        try:
            op = input().strip().upper()
        except (KeyboardInterrupt, EOFError):
            op = "V"

        if op == "1":
            configurar_interface(interfaces)
        elif op == "2":
            configurar_roteamento(interfaces)
        elif op == "3":
            toggle_ip_forward()
        elif op == "4":
            ver_status()
        elif op == "V":
            limpar()
            print(C_DIM + "\n  MoonShield NetForge encerrado.\n" + C_RESET)
            sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if os.geteuid() != 0:
        print(C_ERRO + "\n  [!] Execute como root: sudo python3 ms_netforge.py\n" + C_RESET)
        sys.exit(1)

    menu_principal()


if __name__ == "__main__":
    main()