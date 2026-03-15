"""
suricata/instalador.py  —  MOONSHIELD Sensor v2.0
Instalador e configurador do Suricata.
Deve ser executado como root no Linux (gateway).

Fluxo:
  1  Validar Linux + root
  2  Garantir Suricata instalado
  2b Baixar regras ET Open via suricata-update
  3  Localizar suricata.yaml
  4  Listar interfaces:
       → Usuário escolhe WAN, LAN e opcionalmente MGMT
       → Usuário escolhe modo de captura (só LAN / LAN+WAN / personalizado)
       → Pergunta se quer adicionar outras redes ao HOME_NET
  5  Confirmar com resumo completo
  6  Copiar regras MS
  7  Backup do suricata.yaml
  8  Aplicar patches (HOME_NET multi-rede, rule-files, eve-log, af-packet)
  9  Validar com suricata -T → restaurar backup se falhar
  10 Habilitar + reiniciar serviço
  11 Verificar eve.json
"""

import os
import re
import sys
import shutil
import ipaddress
from pathlib import Path

_AQUI    = Path(__file__).resolve().parent
BASE_DIR = _AQUI.parent

YAML_CANDIDATOS = [
    Path("/etc/suricata/suricata.yaml"),
    Path("/usr/local/etc/suricata/suricata.yaml"),
]
REGRAS_DEST_DIR = Path("/var/lib/suricata/rules/moonshield")
REGRAS_DEST     = REGRAS_DEST_DIR / "ms.rules"
REGRAS_ORIGEM   = _AQUI / "regras_ms.rules"
EVE_JSON        = Path("/var/log/suricata/eve.json")

IFACES_IGNORADAS   = {"lo", "docker0", "podman0", "virbr0"}
PREFIXOS_IGNORADOS = ("br-", "veth", "tun", "wg", "docker", "virbr", "vmnet")

from nucleo.interface import (
    cabecalho, separador, linha_texto, linha_vazia,
    print_resultado, input_campo, aguardar_enter,
    C_DESTAQUE, C_DIM, C_OK, C_ERRO, C_AVISO, C_NORMAL, C_TITULO,
)
from nucleo.utilitarios import is_root, run_cmd, cmd_existe, detectar_gerenciador_pacote


# ══════════════════════════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════

def executar_instalacao(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("INSTALAR / CONFIGURAR SURICATA", C_DESTAQUE)
    linha_texto("Modo: Sensor passivo (IDS) — só monitora, não bloqueia", C_DIM)
    linha_vazia()

    if not _exigir_linux_root():
        aguardar_enter()
        return cfg

    if not _garantir_suricata():
        aguardar_enter()
        return cfg

    _atualizar_regras_et()

    yaml_path = _localizar_suricata_yaml()
    if yaml_path is None:
        print_resultado(False, "Não encontrei o suricata.yaml. Abortando.")
        aguardar_enter()
        return cfg

    separador()

    topo = _escolher_interface()
    if topo is None:
        print_resultado(False, "Configuração de interfaces cancelada. Abortando.")
        aguardar_enter()
        return cfg

    separador()

    if not _copiar_regras_ms():
        aguardar_enter()
        return cfg

    bak = _backup_arquivo(yaml_path)
    if bak:
        print_resultado(True, f"Backup criado: {bak}")
    else:
        print_resultado(False, "Não consegui fazer backup. Abortando.")
        aguardar_enter()
        return cfg

    if not _aplicar_todos_patches(yaml_path, topo):
        aguardar_enter()
        return cfg

    ok, msg = _testar_suricata(yaml_path)
    if not ok:
        print_resultado(False, f"suricata -T falhou: {msg}")
        linha_texto("Restaurando backup...", C_DIM)
        shutil.copy2(bak, yaml_path)
        print_resultado(True, "Backup restaurado.")
        aguardar_enter()
        return cfg

    print_resultado(True, "suricata -T → configuração válida.")
    _corrigir_override_systemd(yaml_path)   

    ok, msg = _reiniciar_servico()
    if ok:
        print_resultado(True, f"Suricata ativo: {msg}")
    else:
        print_resultado(False, f"Problema no serviço: {msg}")
        linha_texto("  journalctl -u suricata --no-pager | tail -20", C_DIM)

    ok_eve, msg_eve = _checar_eve_json()
    if ok_eve:
        print_resultado(True, msg_eve)
    else:
        print_resultado(False, msg_eve)

    # ── Salva topologia completa no config ────────────────────────────────────
    cfg["suricata_yaml"]          = str(yaml_path)
    cfg["interface_lan"]          = topo["iface_lan"]
    cfg["interface_wan"]          = topo["iface_wan"]
    cfg["interface_mgmt"]         = topo.get("iface_mgmt", "")
    cfg["interface_captura"]      = topo["iface_lan"]   # compatibilidade diagnóstico
    cfg["interfaces_monitoradas"] = topo["interfaces_monitoradas"]
    cfg["home_net"]               = topo["home_net"]
    cfg["dns_interno"]            = topo.get("dns_interno", "")
    cfg["eve_path"]               = str(EVE_JSON)
    cfg["suricata_ok"]            = True

    from nucleo.configuracao import salvar_config
    salvar_config(cfg)

    linha_vazia()
    linha_texto("Instalação concluída!", C_OK, "centro")
    linha_vazia()
    aguardar_enter()
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# 1 — AMBIENTE
# ══════════════════════════════════════════════════════════════════════════════

def _exigir_linux_root() -> bool:
    if sys.platform == "win32":
        print_resultado(False, "Instalador Suricata só roda no Linux.")
        return False
    if not is_root():
        print_resultado(False, "Precisa de root. Execute: sudo python3 sensor.py")
        return False
    print_resultado(True, "Linux + root confirmados.")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 2 — SURICATA
# ══════════════════════════════════════════════════════════════════════════════

def _garantir_suricata() -> bool:
    if cmd_existe("suricata"):
        _, out, _ = run_cmd("suricata --version")
        versao = out.split("\n")[0].strip() if out else "versão desconhecida"
        print_resultado(True, f"Suricata já instalado: {versao}")
        return True
    linha_texto("Suricata não encontrado. Instalando...", C_AVISO)
    return _instalar_suricata()


def _instalar_suricata() -> bool:
    mgr = detectar_gerenciador_pacote()
    if mgr is None:
        print_resultado(False, "Gerenciador de pacotes não detectado.")
        return False
    cmds = {
        "apt":    "apt-get install -y suricata",
        "dnf":    "dnf install -y suricata",
        "yum":    "yum install -y suricata",
        "pacman": "pacman -S --noconfirm suricata",
    }
    linha_texto(f"Instalando via {mgr}...", C_DIM)
    code, _, err = run_cmd(cmds[mgr])
    if code != 0:
        print_resultado(False, f"Falha: {err[:120]}")
        return False
    if not cmd_existe("suricata"):
        print_resultado(False, "Binário não encontrado no PATH após instalação.")
        return False
    print_resultado(True, "Suricata instalado com sucesso.")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 2b — ET OPEN
# ══════════════════════════════════════════════════════════════════════════════

def _atualizar_regras_et() -> bool:
    separador()
    linha_texto("REGRAS EMERGING THREATS (ET Open)", C_DESTAQUE)
    linha_vazia()
    linha_texto("  As regras ET Open cobrem ~40.000 ameaças conhecidas.", C_DIM)
    linha_texto("  As regras MS serão adicionadas por cima.", C_DIM)
    linha_vazia()

    if not cmd_existe("suricata-update"):
        linha_texto("suricata-update não encontrado. Tentando instalar...", C_DIM)
        mgr = detectar_gerenciador_pacote()
        cmds_update = {
            "apt":    "apt-get install -y suricata-update",
            "dnf":    "dnf install -y python3-suricata-update",
            "yum":    "yum install -y python3-suricata-update",
            "pacman": "pacman -S --noconfirm suricata-update",
        }
        if mgr and mgr in cmds_update:
            code, _, _ = run_cmd(cmds_update[mgr])
            if code != 0:
                run_cmd("pip3 install suricata-update")

    if not cmd_existe("suricata-update"):
        print_resultado(False, "suricata-update não disponível.")
        linha_texto("  Continuando apenas com regras MS.", C_AVISO)
        linha_vazia()
        return False

    linha_texto("Habilitando fonte ET Open...", C_DIM)
    run_cmd("suricata-update enable-source et/open")
    linha_texto("Baixando regras ET Open... (pode demorar 1-3 min)", C_AVISO)
    linha_vazia()

    code, out, err = run_cmd("suricata-update --no-reload 2>&1")

    if code == 0:
        total_regras = 0
        for linha in (out + err).split("\n"):
            if "rules added" in linha.lower() or "loaded" in linha.lower():
                nums = re.findall(r'\d+', linha)
                if nums:
                    total_regras = max(int(n) for n in nums)
                    break
        if total_regras > 0:
            print_resultado(True, f"ET Open instaladas: {total_regras:,} regras.")
        else:
            print_resultado(True, "Regras ET Open instaladas.")
        linha_texto("  Fonte: Proofpoint ET Open (gratuita)", C_DIM)
        linha_vazia()
        return True
    else:
        saida = (out + err)[:200]
        print_resultado(False, f"suricata-update falhou: {saida}")
        linha_texto("  Continuando apenas com regras MS.", C_AVISO)
        linha_vazia()
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 3 — YAML
# ══════════════════════════════════════════════════════════════════════════════

def _localizar_suricata_yaml() -> Path | None:
    for candidato in YAML_CANDIDATOS:
        if candidato.exists():
            print_resultado(True, f"suricata.yaml encontrado: {candidato}")
            return candidato

    linha_texto("Tentando localizar com find...", C_DIM)
    _, out, _ = run_cmd("find /etc /usr/local/etc -name suricata.yaml 2>/dev/null | head -1")
    if out:
        found = Path(out.strip())
        if found.exists():
            print_resultado(True, f"suricata.yaml encontrado: {found}")
            return found

    caminho_str = input_campo("Informe o caminho completo do suricata.yaml")
    if caminho_str:
        p = Path(caminho_str.strip())
        if p.exists():
            return p
        print_resultado(False, f"Não encontrado: {p}")
    return None


# ══════════════════════════════════════════════════════════════════════════════
# 4 — ESCOLHER INTERFACES  (WAN / LAN / MGMT / MODO DE CAPTURA)
# ══════════════════════════════════════════════════════════════════════════════

def _escolher_interface() -> dict | None:
    """
    Fluxo explícito de configuração de interfaces:

    1. Exibe tabela de interfaces disponíveis
    2. Usuário escolhe a WAN  (saída para internet)
    3. Usuário escolhe a LAN  (rede interna principal → HOME_NET base)
    4. Se sobrar interface, pergunta se é MGMT ou outra rede a monitorar
    5. Escolha do modo de captura: só LAN / LAN+WAN / personalizado
    6. Pergunta se quer adicionar redes extras ao HOME_NET
    7. Exibe resumo e pede confirmação
    """
    ifaces = _listar_interfaces_com_ip_e_rx()

    if not ifaces:
        print_resultado(False, "Nenhuma interface com IP encontrada.")
        return None

    wan_sugerida = _detectar_wan()

    # ── Exibe tabela ──────────────────────────────────────────────────────────
    _exibir_tabela_interfaces(ifaces, wan_sugerida)

    # ── PASSO 1 — Escolher WAN ────────────────────────────────────────────────
    separador()
    linha_texto("PASSO 1 — INTERFACE WAN", C_DESTAQUE)
    linha_vazia()
    linha_texto("  A WAN é a interface conectada à internet (ou à rede externa).", C_DIM)
    linha_texto("  Ela NÃO entra no HOME_NET.", C_DIM)
    linha_vazia()

    idx_wan_sug = next(
        (str(i + 1) for i, f in enumerate(ifaces) if f["nome"] == wan_sugerida), "1"
    )

    while True:
        resp = input_campo("Qual é a WAN? (número)", idx_wan_sug).strip()
        if not resp.isdigit():
            linha_texto("  Digite apenas o número.", C_AVISO)
            continue
        idx = int(resp) - 1
        if 0 <= idx < len(ifaces):
            iface_wan = ifaces[idx]
            break
        linha_texto(f"  Número inválido (1–{len(ifaces)}).", C_AVISO)

    print_resultado(True, f"WAN: {iface_wan['nome']}  ({iface_wan['cidr']})")

    # ── PASSO 2 — Escolher LAN ────────────────────────────────────────────────
    separador()
    linha_texto("PASSO 2 — INTERFACE LAN", C_DESTAQUE)
    linha_vazia()
    linha_texto("  A LAN é a rede interna principal que você quer proteger.", C_DIM)
    linha_texto("  O CIDR dela vira o HOME_NET base.", C_DIM)
    linha_vazia()

    ifaces_sem_wan = [f for f in ifaces if f["nome"] != iface_wan["nome"]]

    if not ifaces_sem_wan:
        print_resultado(False, "Só há uma interface além da WAN. Impossível continuar.")
        return None

    # Re-exibe só as restantes para facilitar
    _exibir_tabela_interfaces(ifaces_sem_wan, "")

    # Sugere a interface com mais RX que não seja WAN
    candidatos = [f for f in ifaces_sem_wan if f["estado"] == "up"]
    idx_lan_sug = "1"
    if candidatos:
        melhor = max(candidatos, key=lambda f: f["rx_pkts"])
        idx_lan_sug = str(ifaces_sem_wan.index(melhor) + 1)

    while True:
        resp = input_campo("Qual é a LAN? (número)", idx_lan_sug).strip()
        if not resp.isdigit():
            linha_texto("  Digite apenas o número.", C_AVISO)
            continue
        idx = int(resp) - 1
        if 0 <= idx < len(ifaces_sem_wan):
            iface_lan = ifaces_sem_wan[idx]
            break
        linha_texto(f"  Número inválido (1–{len(ifaces_sem_wan)}).", C_AVISO)

    print_resultado(True, f"LAN: {iface_lan['nome']}  ({iface_lan['cidr']})")

    # HOME_NET começa com a rede da LAN
    home_net = [str(ipaddress.IPv4Network(iface_lan["cidr"], strict=False))]

    # ── PASSO 3 — MGMT (opcional, só se sobrar interface) ─────────────────────
    iface_mgmt = None
    ifaces_restantes = [
        f for f in ifaces
        if f["nome"] not in (iface_wan["nome"], iface_lan["nome"])
    ]

    if ifaces_restantes:
        separador()
        linha_texto("PASSO 3 — INTERFACE DE GERÊNCIA (MGMT)", C_DESTAQUE)
        linha_vazia()
        linha_texto("  Interface de gerência é usada só para administrar o servidor", C_DIM)
        linha_texto("  (SSH, PuTTY). Ela NÃO é monitorada e NÃO entra no HOME_NET.", C_DIM)
        linha_vazia()

        _exibir_tabela_interfaces(ifaces_restantes, "")

        linha_texto("  Se não tiver interface de gerência, pressione Enter para pular.", C_DIM)
        linha_vazia()

        resp = input_campo("Qual é a MGMT? (número ou Enter para pular)", "").strip()

        if resp and resp.isdigit():
            idx = int(resp) - 1
            if 0 <= idx < len(ifaces_restantes):
                iface_mgmt = ifaces_restantes[idx]
                print_resultado(True, f"MGMT: {iface_mgmt['nome']}  ({iface_mgmt['cidr']})")
            else:
                linha_texto("  Número inválido — pulando MGMT.", C_AVISO)
        else:
            linha_texto("  Sem interface de gerência configurada.", C_DIM)

    # ── PASSO 4 — Modo de captura ─────────────────────────────────────────────
    separador()
    linha_texto("PASSO 4 — MODO DE CAPTURA", C_DESTAQUE)
    linha_vazia()
    linha_texto("  Quais interfaces o Suricata vai monitorar?", C_DIM)
    linha_vazia()
    linha_texto(f"  [1]  Só LAN           ({iface_lan['nome']})", C_NORMAL)
    linha_texto(f"  [2]  LAN + WAN        ({iface_lan['nome']} + {iface_wan['nome']})", C_NORMAL)
    linha_texto(f"  [3]  Personalizado    (você escolhe)", C_NORMAL)
    linha_vazia()

    while True:
        modo = input_campo("Modo de captura", "2").strip()
        if modo in ("1", "2", "3"):
            break
        linha_texto("  Digite 1, 2 ou 3.", C_AVISO)

    if modo == "1":
        interfaces_monitoradas = [iface_lan["nome"]]

    elif modo == "2":
        interfaces_monitoradas = [iface_lan["nome"], iface_wan["nome"]]

    else:
        # Modo personalizado — exibe todas exceto MGMT
        ifaces_disponiveis = [
            f for f in ifaces
            if iface_mgmt is None or f["nome"] != iface_mgmt["nome"]
        ]
        linha_vazia()
        linha_texto("  Interfaces disponíveis para monitoramento:", C_AVISO)
        linha_vazia()
        _exibir_tabela_interfaces(ifaces_disponiveis, "")
        linha_texto("  Digite os números separados por vírgula.", C_DIM)
        linha_texto("  Exemplo: 1,2", C_DIM)
        linha_vazia()

        interfaces_monitoradas = []
        while not interfaces_monitoradas:
            resp = input_campo("Quais interfaces monitorar?", "").strip()
            for parte in resp.split(","):
                parte = parte.strip()
                if parte.isdigit():
                    idx = int(parte) - 1
                    if 0 <= idx < len(ifaces_disponiveis):
                        nome = ifaces_disponiveis[idx]["nome"]
                        if nome not in interfaces_monitoradas:
                            interfaces_monitoradas.append(nome)
            if not interfaces_monitoradas:
                linha_texto("  Selecione ao menos uma interface.", C_AVISO)

    linha_vazia()
    linha_texto("  Interfaces que serão monitoradas:", C_AVISO)
    for nome in interfaces_monitoradas:
        info = next((f for f in ifaces if f["nome"] == nome), {})
        linha_texto(f"    • {nome}  {info.get('cidr', '')}", C_OK)

    # ── PASSO 5 — HOME_NET adicional ──────────────────────────────────────────
    # Redes das interfaces monitoradas que ainda não estão no HOME_NET
    redes_candidatas = []
    for nome in interfaces_monitoradas:
        if nome == iface_lan["nome"]:
            continue  # já está no HOME_NET
        info = next((f for f in ifaces if f["nome"] == nome), None)
        if not info:
            continue
        rede = str(ipaddress.IPv4Network(info["cidr"], strict=False))
        if rede not in home_net:
            redes_candidatas.append({"nome": nome, "cidr": info["cidr"], "rede": rede})

    if redes_candidatas:
        separador()
        linha_texto("PASSO 5 — HOME_NET ADICIONAL", C_DESTAQUE)
        linha_vazia()
        linha_texto("  Deseja adicionar outras redes monitoradas ao HOME_NET?", C_DIM)
        linha_texto("  Redes no HOME_NET são tratadas como internas nas regras.", C_DIM)
        linha_vazia()

        for i, r in enumerate(redes_candidatas, start=1):
            tag = "← WAN" if r["nome"] == iface_wan["nome"] else ""
            linha_texto(f"  [{i}]  {r['nome']:<12} {r['cidr']:<20} {tag}", C_DIM)

        linha_vazia()
        linha_texto("  Digite os números ou Enter para pular.", C_DIM)
        linha_vazia()

        resp = input_campo("Adicionar ao HOME_NET?", "").strip()
        if resp:
            for parte in resp.split(","):
                parte = parte.strip()
                if parte.isdigit():
                    idx = int(parte) - 1
                    if 0 <= idx < len(redes_candidatas):
                        rede_extra = redes_candidatas[idx]["rede"]
                        if rede_extra not in home_net:
                            home_net.append(rede_extra)
                            print_resultado(
                                True,
                                f"Adicionado ao HOME_NET: {rede_extra} ({redes_candidatas[idx]['nome']})"
                            )

    # ── RESUMO FINAL ──────────────────────────────────────────────────────────
    linha_vazia()
    separador()
    linha_texto("RESUMO FINAL", C_DESTAQUE)
    linha_vazia()

    linha_texto(f"  WAN   : {iface_wan['nome']:<12} {iface_wan['cidr']}", C_DIM)
    linha_texto(f"  LAN   : {iface_lan['nome']:<12} {iface_lan['cidr']}", C_OK)

    if iface_mgmt:
        linha_texto(f"  MGMT  : {iface_mgmt['nome']:<12} {iface_mgmt['cidr']}  (fora do monitoramento)", C_DIM)
    else:
        linha_texto(f"  MGMT  : (não configurada)", C_DIM)

    linha_vazia()
    linha_texto("  HOME_NET (redes protegidas pelas regras):", C_AVISO)
    for rede in home_net:
        linha_texto(f"    • {rede}", C_OK)

    linha_vazia()
    linha_texto("  Interfaces monitoradas pelo Suricata:", C_AVISO)
    for nome in interfaces_monitoradas:
        info = next((f for f in ifaces if f["nome"] == nome), {})
        tag = ""
        if nome == iface_wan["nome"]:
            tag = "  ← WAN"
        elif nome == iface_lan["nome"]:
            tag = "  ← LAN"
        linha_texto(f"    • {nome}  {info.get('cidr', '')}{tag}", C_DIM)

    linha_vazia()
    linha_texto("  O que vai acontecer:", C_AVISO)
    linha_texto("    • Regras MS copiadas para o sistema", C_DIM)
    linha_texto("    • suricata.yaml reescrito com as interfaces selecionadas", C_DIM)
    linha_texto("    • HOME_NET configurado com as redes selecionadas", C_DIM)
    linha_texto("    • Configuração validada com suricata -T", C_DIM)
    linha_texto("    • Suricata reiniciado", C_DIM)
    linha_vazia()

    confirma = input_campo("Confirmar e aplicar? (s/n)", "s")
    if confirma.strip().lower() != "s":
        return None

    return {
        "iface_lan":              iface_lan["nome"],
        "iface_wan":              iface_wan["nome"],
        "iface_mgmt":             iface_mgmt["nome"] if iface_mgmt else "",
        "home_net":               home_net,
        "dns_interno":            iface_lan["ip"],
        "todas_ifaces":           ifaces,
        "interfaces_monitoradas": interfaces_monitoradas,
    }


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS DE EXIBIÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _exibir_tabela_interfaces(ifaces: list, iface_wan: str):
    linha_texto("INTERFACES DISPONÍVEIS", C_TITULO, "centro")
    linha_vazia()
    print("\033[36m║\033[0m  " + "-" * 62)
    print(
        "\033[36m║\033[0m  "
        + f"{'Nº':<4} {'Interface':<12} {'IP / CIDR':<22} {'RX (pkts)':<14} {'Info'}"
    )
    print("\033[36m║\033[0m  " + "-" * 62)

    for i, iface in enumerate(ifaces, start=1):
        rx_str = f"{iface['rx_pkts']:,}" if iface['rx_pkts'] >= 0 else "?"
        info   = ""
        cor    = C_NORMAL
        if iface["nome"] == iface_wan:
            info = "← WAN detectada"
            cor  = C_DIM
        elif iface["estado"] != "up":
            info = f"[{iface['estado']}]"
            cor  = C_DIM
        print(
            "\033[36m║\033[0m  "
            + cor
            + f"  {i:<3} {iface['nome']:<12} {iface['cidr']:<22} {rx_str:<14} {info}"
            + "\033[0m"
        )

    print("\033[36m║\033[0m  " + "-" * 62)
    linha_vazia()


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS DE INTERFACES
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_wan() -> str:
    _, out, _ = run_cmd("ip route show default")
    tokens = out.split()
    for i, t in enumerate(tokens):
        if t == "dev" and i + 1 < len(tokens):
            return tokens[i + 1]
    return ""


def _listar_interfaces_com_ip_e_rx() -> list:
    _, out_addr, _  = run_cmd("ip -o -4 addr show")
    _, out_stats, _ = run_cmd("ip -s link show")

    rx_map       = {}
    linhas_stats = out_stats.splitlines()
    iface_atual  = None
    aguarda_rx   = False

    for linha in linhas_stats:
        linha = linha.strip()
        m = re.match(r"^\d+:\s+(\S+?):", linha)
        if m:
            iface_atual = m.group(1)
            aguarda_rx  = False
            continue
        if "RX:" in linha and iface_atual:
            aguarda_rx = True
            continue
        if aguarda_rx and iface_atual:
            numeros = linha.split()
            if len(numeros) >= 2:
                try:
                    rx_map[iface_atual] = int(numeros[1])
                except ValueError:
                    rx_map[iface_atual] = 0
            aguarda_rx = False

    ifaces = []
    vistas = set()

    for linha in out_addr.splitlines():
        partes = linha.split()
        if len(partes) < 4:
            continue
        nome = partes[1].rstrip(":")
        if nome in IFACES_IGNORADAS:
            continue
        if any(nome.startswith(p) for p in PREFIXOS_IGNORADOS):
            continue
        if nome in vistas:
            continue
        try:
            idx     = partes.index("inet")
            ip_cidr = partes[idx + 1]
            ip      = ip_cidr.split("/")[0]
        except (ValueError, IndexError):
            continue
        vistas.add(nome)
        estado_path = Path(f"/sys/class/net/{nome}/operstate")
        try:
            estado = estado_path.read_text().strip()
        except Exception:
            estado = "?"
        ifaces.append({
            "nome":    nome,
            "ip":      ip,
            "cidr":    ip_cidr,
            "estado":  estado,
            "rx_pkts": rx_map.get(nome, -1),
        })

    return ifaces


def _listar_interfaces_com_ip() -> list:
    """Compatibilidade com diagnostico.py"""
    return [
        {
            "nome":   i["nome"],
            "ip":     i["ip"],
            "cidr":   i["cidr"],
            "rede":   str(ipaddress.IPv4Network(i["cidr"], strict=False)),
            "estado": i["estado"],
        }
        for i in _listar_interfaces_com_ip_e_rx()
    ]


# ══════════════════════════════════════════════════════════════════════════════
# 6 — REGRAS MS
# ══════════════════════════════════════════════════════════════════════════════

def _copiar_regras_ms() -> bool:
    if not REGRAS_ORIGEM.exists():
        print_resultado(False, f"Regras não encontradas: {REGRAS_ORIGEM}")
        return False
    try:
        REGRAS_DEST_DIR.mkdir(parents=True, exist_ok=True)
        conteudo_rules = REGRAS_ORIGEM.read_text(encoding="utf-8-sig")
        REGRAS_DEST.write_text(conteudo_rules, encoding="utf-8")
        print_resultado(True, f"Regras MS copiadas → {REGRAS_DEST}")

        etc_dest_dir = Path("/etc/suricata/rules/moonshield")
        etc_dest_dir.mkdir(parents=True, exist_ok=True)
        (etc_dest_dir / "ms.rules").write_text(conteudo_rules, encoding="utf-8")
        print_resultado(True, f"Regras MS copiadas → {etc_dest_dir / 'ms.rules'}")

        return True
    except Exception as e:
        print_resultado(False, f"Erro ao copiar regras: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 7 — BACKUP
# ══════════════════════════════════════════════════════════════════════════════

def _backup_arquivo(path: Path) -> Path | None:
    bak = Path(str(path) + ".ms.bak")
    try:
        shutil.copy2(path, bak)
        return bak
    except Exception as e:
        print_resultado(False, f"Backup falhou: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 8 — PATCHES
# ══════════════════════════════════════════════════════════════════════════════

def _aplicar_todos_patches(yaml_path: Path, topo: dict) -> bool:
    try:
        conteudo = yaml_path.read_text(encoding="utf-8")
    except Exception as e:
        print_resultado(False, f"Não consigo ler suricata.yaml: {e}")
        return False

    conteudo = _patch_home_net(conteudo, topo["home_net"])
    conteudo = _patch_rule_files(conteudo)
    conteudo = _patch_eve_log(conteudo)
    conteudo = _sanitizar_e_patch_af_packet(conteudo, topo["interfaces_monitoradas"])

    try:
        yaml_path.write_text(conteudo, encoding="utf-8")
        print_resultado(True, "Patches aplicados no suricata.yaml.")
        return True
    except Exception as e:
        print_resultado(False, f"Erro ao salvar suricata.yaml: {e}")
        return False


def _patch_home_net(conteudo: str, home_net: list) -> str:
    if not home_net:
        return conteudo

    valor     = "[" + ",".join(home_net) + "]"
    nova_line = f'    HOME_NET: "{valor}"'

    linhas = conteudo.split("\n")
    nova   = []
    ok     = False

    for linha in linhas:
        if linha.strip().startswith("HOME_NET:"):
            nova.append(nova_line)
            ok = True
        else:
            nova.append(linha)

    if not ok:
        nova2 = []
        for linha in nova:
            nova2.append(linha)
            if "address-groups:" in linha:
                nova2.append(nova_line)
                ok = True
        nova = nova2

    if not ok:
        nova += ["\nvars:", "  address-groups:", nova_line]

    return "\n".join(nova)


def _patch_rule_files(conteudo: str) -> str:
    MARCADOR = "moonshield/ms.rules"
    ENTRADA  = "  - moonshield/ms.rules"

    if MARCADOR in conteudo:
        return conteudo

    linhas   = conteudo.split("\n")
    nova     = []
    inserido = False

    for linha in linhas:
        nova.append(linha)
        if not inserido and "rule-files:" in linha.lower():
            nova.append(ENTRADA)
            inserido = True

    if not inserido:
        nova += ["\nrule-files:", ENTRADA]

    return "\n".join(nova)


def _patch_eve_log(conteudo: str) -> str:
    if "/var/log/suricata/eve.json" in conteudo:
        return conteudo

    EVE_BLOCK = (
        "\n  # == MOONSHIELD: eve-log ==\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        "      filename: /var/log/suricata/eve.json\n"
        "      types:\n"
        "        - alert\n"
        "        - dns:\n"
        "            query: yes\n"
        "            answer: yes\n"
        "        - http:\n"
        "            extended: yes\n"
        "        - tls:\n"
        "            extended: yes\n"
    )

    linhas   = conteudo.split("\n")
    nova     = []
    inserido = False

    for linha in linhas:
        nova.append(linha)
        if not inserido and linha.strip().lower().startswith("outputs:"):
            nova.append(EVE_BLOCK)
            inserido = True

    if not inserido:
        nova += ["\noutputs:", EVE_BLOCK]

    return "\n".join(nova)


def _sanitizar_e_patch_af_packet(conteudo: str, interfaces: list) -> str:
    """
    Reescreve af-packet apenas com as interfaces selecionadas pelo usuário.
    LAN = cluster-id 99, demais incrementam (100, 101...).
    Remove eth0/eth1/placeholders originais.
    """
    linhas_bloco = ["af-packet:", "  # == MOONSHIELD =="]

    for i, iface in enumerate(interfaces):
        linhas_bloco += [
            f"  - interface: {iface}",
            f"    threads: auto",
            f"    cluster-id: {99 + i}",
            f"    cluster-type: cluster_flow",
            f"    defrag: yes",
        ]

    bloco_af = "\n".join(linhas_bloco) + "\n"

    if re.search(r"(?m)^af-packet:", conteudo):
        conteudo = re.sub(
            r"(?m)^af-packet:\n(?:^[ \t].*\n)*",
            bloco_af,
            conteudo,
        )
    else:
        conteudo += f"\n{bloco_af}"

    bloco_pcap = "pcap:\n  - interface: none\n"
    if re.search(r"(?m)^pcap:", conteudo):
        conteudo = re.sub(
            r"(?m)^pcap:\n(?:^[ \t].*\n)*",
            bloco_pcap,
            conteudo,
        )
    else:
        conteudo += f"\n{bloco_pcap}"

    nomes = ", ".join(interfaces)
    print_resultado(True, f"af-packet configurado → {nomes}")
    return conteudo


# ══════════════════════════════════════════════════════════════════════════════
# 9 — VALIDAR
# ══════════════════════════════════════════════════════════════════════════════

def _testar_suricata(yaml_path: Path) -> tuple:
    linha_texto("Validando configuração com suricata -T ...", C_DIM)
    linha_texto("(isso pode levar alguns segundos)", C_DIM)
    _, out, err = run_cmd(f"suricata -T -c {yaml_path} 2>&1")
    saida = (out + err).strip()

    erros = [l.strip() for l in saida.split("\n") if l.strip().startswith("E:")]

    if not erros:
        warnings = [l.strip() for l in saida.split("\n") if l.strip().startswith("W:")]
        if warnings:
            linha_texto("  Avisos (não bloqueiam):", C_AVISO)
            for w in warnings[:3]:
                linha_texto(f"    {w}", C_DIM)
        return True, "OK"

    linha_texto("  Erros encontrados:", C_ERRO)
    for e in erros[:5]:
        linha_texto(f"    {e}", C_ERRO)
    return False, erros[0]


# ══════════════════════════════════════════════════════════════════════════════
# 9b — CORRIGIR OVERRIDE SYSTEMD
# ══════════════════════════════════════════════════════════════════════════════

def _corrigir_override_systemd(yaml_path: Path) -> None:
    """
    O apt cria /etc/systemd/system/suricata.service.d/override.conf
    com --pcap=<iface> hardcoded, ignorando o af-packet do yaml.
    Este método sobrescreve o override para usar apenas o yaml.
    """
    override = Path("/etc/systemd/system/suricata.service.d/override.conf")
    try:
        override.parent.mkdir(parents=True, exist_ok=True)
        override.write_text(
            "[Service]\n"
            "ExecStart=\n"
            f"ExecStart=/usr/bin/suricata -D -c {yaml_path} --pidfile /run/suricata.pid\n"
        )
        run_cmd("systemctl daemon-reload")
        print_resultado(True, "override.conf corrigido → af-packet ativo.")
    except Exception as e:
        print_resultado(False, f"Não consegui corrigir override.conf: {e}")

# ══════════════════════════════════════════════════════════════════════════════
# 10 — REINICIAR
# ══════════════════════════════════════════════════════════════════════════════

def _reiniciar_servico() -> tuple:
    if not cmd_existe("systemctl"):
        return False, "systemd não encontrado"

    linha_texto("Habilitando e reiniciando o serviço Suricata...", C_DIM)
    run_cmd("systemctl enable --now suricata")
    run_cmd("systemctl restart suricata")

    code, out, _ = run_cmd("systemctl is-active suricata")
    status = out.strip()

    if code == 0 and status == "active":
        return True, "active"
    return False, status or "inativo"


# ══════════════════════════════════════════════════════════════════════════════
# 11 — EVE.JSON
# ══════════════════════════════════════════════════════════════════════════════

def _checar_eve_json() -> tuple:
    if EVE_JSON.exists():
        tam = EVE_JSON.stat().st_size
        return True, f"eve.json encontrado ({tam:,} bytes)"
    return False, "eve.json ainda não existe. Use [9] Diagnóstico para verificar."


# ══════════════════════════════════════════════════════════════════════════════
# PÚBLICO
# ══════════════════════════════════════════════════════════════════════════════

def detectar_interfaces() -> list:
    return [i["nome"] for i in _listar_interfaces_com_ip()]