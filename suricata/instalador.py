"""
suricata/instalador.py
Instalador e configurador do Suricata para o Jarvis Guard Sensor.
Deve ser executado como root no Linux (gateway).

Fluxo:
  1  Validar Linux + root
  2  Garantir Suricata (instalar se necessário)
  2b Baixar regras Emerging Threats (ET Open) via suricata-update
  3  Localizar suricata.yaml
  4  Listar interfaces e perguntar UMA SÓ COISA: qual monitorar
  5  Confirmar com resumo simples
  6  Copiar regras JG (sempre sobrescrever)
  7  Backup do suricata.yaml
  8  Aplicar patches (HOME_NET, rule-files, eve-log, af-packet)
  8b Sanitizar yaml (remove eth0 e placeholders, sobrescreve af-packet inteiro)
  9  Validar com suricata -T  →  restaurar backup se falhar
  10 Habilitar + reiniciar serviço
  11 Verificar eve.json
"""

import os
import re
import sys
import shutil
import ipaddress
from pathlib import Path

# ── Raiz do projeto (sempre absoluto, independe de cwd) ──────────────────────
_AQUI    = Path(__file__).resolve().parent     # suricata/
BASE_DIR = _AQUI.parent                        # raiz do projeto

# ── Caminhos fixos do sistema ─────────────────────────────────────────────────
YAML_CANDIDATOS = [
    Path("/etc/suricata/suricata.yaml"),
    Path("/usr/local/etc/suricata/suricata.yaml"),
]
REGRAS_DEST_DIR = Path("/var/lib/suricata/rules/jarvis-guard")
REGRAS_DEST     = REGRAS_DEST_DIR / "jg.rules"
REGRAS_ORIGEM   = _AQUI / "regras_jg.rules"
EVE_JSON        = Path("/var/log/suricata/eve.json")

# Interfaces virtuais que devem ser ignoradas
IFACES_IGNORADAS   = {"lo", "docker0", "podman0", "virbr0"}
PREFIXOS_IGNORADOS = ("br-", "veth", "tun", "wg", "docker", "virbr", "vmnet")

# ── Imports visuais do nucleo ─────────────────────────────────────────────────
from nucleo.interface import (
    cabecalho, separador, linha_texto, linha_vazia,
    print_resultado, input_campo, aguardar_enter,
    C_DESTAQUE, C_DIM, C_OK, C_ERRO, C_AVISO, C_NORMAL, C_TITULO,
)
from nucleo.utilitarios import is_root, run_cmd, cmd_existe, detectar_gerenciador_pacote


# ══════════════════════════════════════════════════════════════════════════════
# PONTO DE ENTRADA PÚBLICO
# ══════════════════════════════════════════════════════════════════════════════

def executar_instalacao(cfg: dict) -> dict:
    """Fluxo completo de instalação / configuração do Suricata."""

    cabecalho(cfg)
    linha_texto("INSTALAR / CONFIGURAR SURICATA", C_DESTAQUE)
    linha_texto("Modo: Sensor passivo (IDS) — só monitora, não bloqueia", C_DIM)
    linha_vazia()

    # ── 1 ─ Ambiente ──────────────────────────────────────────────────────────
    if not _exigir_linux_root():
        aguardar_enter()
        return cfg

    # ── 2 ─ Suricata ──────────────────────────────────────────────────────────
    if not _garantir_suricata():
        aguardar_enter()
        return cfg

    # ── 2b ─ Regras Emerging Threats (ET Open) ────────────────────────────────
    _atualizar_regras_et()

    # ── 3 ─ suricata.yaml ─────────────────────────────────────────────────────
    yaml_path = _localizar_suricata_yaml()
    if yaml_path is None:
        print_resultado(False, "Não encontrei o suricata.yaml. Abortando.")
        aguardar_enter()
        return cfg

    separador()

    # ── 4 ─ Escolher interface de monitoramento (UMA PERGUNTA SÓ) ────────────
    topo = _escolher_interface()
    if topo is None:
        print_resultado(False, "Nenhuma interface selecionada. Abortando.")
        aguardar_enter()
        return cfg

    separador()

    # ── 6 ─ Copiar regras JG ──────────────────────────────────────────────────
    if not _copiar_regras_jg():
        aguardar_enter()
        return cfg

    # ── 7 ─ Backup ────────────────────────────────────────────────────────────
    bak = _backup_arquivo(yaml_path)
    if bak:
        print_resultado(True, f"Backup criado: {bak}")
    else:
        print_resultado(False, "Não consegui fazer backup do suricata.yaml. Abortando.")
        aguardar_enter()
        return cfg

    # ── 8 ─ Patches ───────────────────────────────────────────────────────────
    if not _aplicar_todos_patches(yaml_path, topo):
        aguardar_enter()
        return cfg

    # ── 9 ─ Validar ───────────────────────────────────────────────────────────
    ok, msg = _testar_suricata(yaml_path)
    if not ok:
        print_resultado(False, f"suricata -T falhou: {msg}")
        linha_texto("Restaurando backup...", C_DIM)
        shutil.copy2(bak, yaml_path)
        print_resultado(True, "Backup restaurado.")
        aguardar_enter()
        return cfg

    print_resultado(True, "suricata -T → configuração válida.")

    # ── 10 ─ Reiniciar ────────────────────────────────────────────────────────
    ok, msg = _reiniciar_servico()
    if ok:
        print_resultado(True, f"Suricata ativo: {msg}")
    else:
        print_resultado(False, f"Problema no serviço: {msg}")
        linha_texto("  journalctl -u suricata --no-pager | tail -20", C_DIM)

    # ── 11 ─ eve.json ─────────────────────────────────────────────────────────
    ok_eve, msg_eve = _checar_eve_json()
    if ok_eve:
        print_resultado(True, msg_eve)
    else:
        print_resultado(False, msg_eve)

    # ── Persistir topologia no config.json ────────────────────────────────────
    cfg["suricata_yaml"]     = str(yaml_path)
    cfg["interface_captura"] = topo["iface_lan"]
    cfg["interface_wan"]     = topo.get("iface_wan", "")
    cfg["home_net"]          = topo["home_net"]
    cfg["dns_interno"]       = topo.get("dns_interno", "")
    cfg["eve_path"]          = str(EVE_JSON)

    from nucleo.configuracao import salvar_config
    salvar_config(cfg)

    linha_vazia()
    linha_texto("Instalação concluída!", C_OK, "centro")
    linha_vazia()
    aguardar_enter()
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# 1 ─ VALIDAÇÃO DE AMBIENTE
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
# 2 ─ GARANTIR SURICATA
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
        print_resultado(False, "Gerenciador de pacotes não detectado (apt/dnf/yum/pacman).")
        return False

    cmds = {
        "apt":    "apt-get install -y suricata",
        "dnf":    "dnf install -y suricata",
        "yum":    "yum install -y suricata",
        "pacman": "pacman -S --noconfirm suricata",
    }

    linha_texto(f"Instalando via {mgr}... (pode demorar alguns minutos)", C_DIM)
    code, _, err = run_cmd(cmds[mgr])
    if code != 0:
        print_resultado(False, f"Falha na instalação: {err[:120]}")
        return False

    if not cmd_existe("suricata"):
        print_resultado(False, "Suricata instalado mas binário não encontrado no PATH.")
        return False

    print_resultado(True, "Suricata instalado com sucesso.")
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 2b ─ REGRAS EMERGING THREATS (ET Open)
# ══════════════════════════════════════════════════════════════════════════════

def _atualizar_regras_et() -> bool:
    """
    Baixa e instala as regras Emerging Threats Open via suricata-update.
    Não falha a instalação se indisponível — o sensor funciona só com as JG.
    """
    separador()
    linha_texto("REGRAS EMERGING THREATS (ET Open)", C_DESTAQUE)
    linha_vazia()
    linha_texto("  As regras ET Open são gratuitas e cobrem ~40.000 ameaças.", C_DIM)
    linha_texto("  As regras JG do Jarvis Guard serão adicionadas por cima.", C_DIM)
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
        linha_texto("  Continuando apenas com regras JG (cobertura reduzida).", C_AVISO)
        linha_vazia()
        return False

    linha_texto("Habilitando fonte Emerging Threats Open...", C_DIM)
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
            print_resultado(True, "Regras ET Open baixadas e instaladas.")

        linha_texto("  Fonte: Proofpoint ET Open (gratuita)", C_DIM)
        linha_vazia()
        return True
    else:
        saida = (out + err)[:200]
        print_resultado(False, f"suricata-update falhou: {saida}")
        linha_texto("  Continuando apenas com regras JG.", C_AVISO)
        linha_vazia()
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 3 ─ LOCALIZAR suricata.yaml
# ══════════════════════════════════════════════════════════════════════════════

def _localizar_suricata_yaml() -> Path | None:
    for candidato in YAML_CANDIDATOS:
        if candidato.exists():
            print_resultado(True, f"suricata.yaml encontrado: {candidato}")
            return candidato

    linha_texto("suricata.yaml não encontrado nos caminhos padrão.", C_AVISO)
    linha_texto("Tentando localizar com find...", C_DIM)
    _, out, _ = run_cmd("find /etc /usr/local/etc -name suricata.yaml 2>/dev/null | head -1")
    if out:
        found = Path(out.strip())
        if found.exists():
            print_resultado(True, f"suricata.yaml encontrado: {found}")
            return found

    linha_vazia()
    caminho_str = input_campo("Informe o caminho completo do suricata.yaml")
    if caminho_str:
        p = Path(caminho_str.strip())
        if p.exists():
            print_resultado(True, f"Usando: {p}")
            return p
        print_resultado(False, f"Arquivo não encontrado: {p}")

    return None


# ══════════════════════════════════════════════════════════════════════════════
# 4 ─ ESCOLHER INTERFACE (UMA PERGUNTA SÓ)
# ══════════════════════════════════════════════════════════════════════════════

def _escolher_interface() -> dict | None:
    """
    Lista as interfaces disponíveis com IP e tráfego RX.
    Usuário escolhe apenas o NÚMERO da interface que quer monitorar.
    WAN, HOME_NET e DNS são deduzidos automaticamente — sem perguntas extras.
    """
    ifaces = _listar_interfaces_com_ip_e_rx()

    if not ifaces:
        print_resultado(False, "Nenhuma interface com IP encontrada.")
        return None

    # ── Detecta WAN pela rota padrão (só para informação, não pergunta) ───────
    iface_wan = _detectar_wan()

    linha_texto("INTERFACES DE REDE DISPONÍVEIS", C_TITULO, "centro")
    linha_vazia()
    linha_texto("  Escolha a interface da rede que você quer monitorar.", C_DIM)
    linha_texto("  Normalmente é a interface da rede interna (laboratório, LAN).", C_DIM)
    linha_vazia()

    # ── Exibe tabela de interfaces ────────────────────────────────────────────
    print("\033[36m║\033[0m  " + "-" * 58)
    print(
        "\033[36m║\033[0m  "
        + f"{'Nº':<4} {'Interface':<12} {'IP / CIDR':<22} {'RX (pkts)':<14} {'Info'}"
    )
    print("\033[36m║\033[0m  " + "-" * 58)

    for i, iface in enumerate(ifaces, start=1):
        rx_str  = f"{iface['rx_pkts']:,}" if iface['rx_pkts'] >= 0 else "?"
        info    = ""
        cor     = C_NORMAL

        if iface["nome"] == iface_wan:
            info = "← internet (WAN)"
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

    print("\033[36m║\033[0m  " + "-" * 58)
    linha_vazia()

    # ── Sugere a interface com mais RX que não seja WAN ───────────────────────
    candidatos = [f for f in ifaces if f["nome"] != iface_wan and f["estado"] == "up"]
    if candidatos:
        melhor  = max(candidatos, key=lambda f: f["rx_pkts"])
        sugest  = str(ifaces.index(melhor) + 1)
    else:
        sugest = "1"

    # ── Uma única pergunta ────────────────────────────────────────────────────
    while True:
        resp = input_campo("Qual interface monitorar? (número)", sugest).strip()
        if not resp.isdigit():
            linha_texto("  Digite apenas o número da interface.", C_AVISO)
            continue
        idx = int(resp) - 1
        if 0 <= idx < len(ifaces):
            escolhida = ifaces[idx]
            break
        linha_texto(f"  Número inválido. Digite entre 1 e {len(ifaces)}.", C_AVISO)

    # ── Deduz HOME_NET e DNS do CIDR da interface escolhida ───────────────────
    home_net   = [str(ipaddress.IPv4Network(escolhida["cidr"], strict=False))]
    dns_intern = escolhida["ip"]   # IP da própria interface como DNS padrão

    # ── Resumo simples para confirmar ─────────────────────────────────────────
    linha_vazia()
    separador()
    linha_texto("RESUMO", C_DESTAQUE)
    linha_vazia()
    linha_texto(f"  Monitorar : {escolhida['nome']}  ({escolhida['cidr']})", C_OK)
    linha_texto(f"  HOME_NET  : {home_net[0]}", C_DIM)
    linha_texto(f"  DNS padrão: {dns_intern}", C_DIM)
    linha_vazia()
    linha_texto("  O que vai acontecer:", C_AVISO)
    linha_texto("    • Regras JG serão copiadas para o sistema", C_DIM)
    linha_texto("    • suricata.yaml será reescrito com esta interface", C_DIM)
    linha_texto("    • eth0 e outros placeholders serão removidos", C_DIM)
    linha_texto("    • Configuração validada com suricata -T", C_DIM)
    linha_texto("    • Suricata reiniciado", C_DIM)
    linha_vazia()

    confirma = input_campo("Confirmar e aplicar? (s/n)", "s")
    if confirma.strip().lower() != "s":
        return None

    return {
        "iface_lan":    escolhida["nome"],
        "iface_wan":    iface_wan,
        "home_net":     home_net,
        "dns_interno":  dns_intern,
        "todas_ifaces": ifaces,
    }


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS DE DETECÇÃO DE INTERFACES
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_wan() -> str:
    """Detecta interface WAN pela rota padrão do sistema."""
    _, out, _ = run_cmd("ip route show default")
    tokens = out.split()
    for i, t in enumerate(tokens):
        if t == "dev" and i + 1 < len(tokens):
            return tokens[i + 1]
    return ""


def _listar_interfaces_com_ip_e_rx() -> list:
    """
    Retorna lista de interfaces com IP, CIDR, estado e contagem de pacotes RX.
    Exclui lo, docker, bridges virtuais, etc.
    """
    _, out_addr, _ = run_cmd("ip -o -4 addr show")
    _, out_stats, _ = run_cmd("ip -s link show")

    # ── Parse de RX por interface ─────────────────────────────────────────────
    rx_map = {}
    linhas_stats = out_stats.splitlines()
    iface_atual  = None
    aguarda_rx   = False

    for linha in linhas_stats:
        linha = linha.strip()
        # Linha de interface: "2: enp0s3: <...>"
        m = re.match(r"^\d+:\s+(\S+?):", linha)
        if m:
            iface_atual = m.group(1)
            aguarda_rx  = False
            continue
        # Linha "RX:  bytes packets ..."
        if "RX:" in linha and iface_atual:
            aguarda_rx = True
            continue
        # Linha seguinte ao RX: tem os números
        if aguarda_rx and iface_atual:
            numeros = linha.split()
            if len(numeros) >= 2:
                try:
                    rx_map[iface_atual] = int(numeros[1])   # pkts
                except ValueError:
                    rx_map[iface_atual] = 0
            aguarda_rx = False

    # ── Parse de endereços ────────────────────────────────────────────────────
    ifaces  = []
    vistas  = set()

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
            "nome":     nome,
            "ip":       ip,
            "cidr":     ip_cidr,
            "estado":   estado,
            "rx_pkts":  rx_map.get(nome, -1),
        })

    return ifaces


def _listar_interfaces_com_ip() -> list:
    """Compatibilidade com diagnostico.py — retorna formato original."""
    ifaces_rx = _listar_interfaces_com_ip_e_rx()
    return [
        {
            "nome":   i["nome"],
            "ip":     i["ip"],
            "cidr":   i["cidr"],
            "rede":   str(ipaddress.IPv4Network(i["cidr"], strict=False)),
            "estado": i["estado"],
        }
        for i in ifaces_rx
    ]


# ══════════════════════════════════════════════════════════════════════════════
# 6 ─ COPIAR REGRAS JG
# ══════════════════════════════════════════════════════════════════════════════

def _copiar_regras_jg() -> bool:
    if not REGRAS_ORIGEM.exists():
        print_resultado(False, f"Regras não encontradas: {REGRAS_ORIGEM}")
        linha_texto("Certifique-se de que suricata/regras_jg.rules existe no projeto.", C_DIM)
        return False
    try:
        REGRAS_DEST_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REGRAS_ORIGEM, REGRAS_DEST)
        print_resultado(True, f"Regras JG copiadas → {REGRAS_DEST}")
        return True
    except Exception as e:
        print_resultado(False, f"Erro ao copiar regras: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 7 ─ BACKUP
# ══════════════════════════════════════════════════════════════════════════════

def _backup_arquivo(path: Path) -> Path | None:
    bak = Path(str(path) + ".jg.bak")
    try:
        shutil.copy2(path, bak)
        return bak
    except Exception as e:
        print_resultado(False, f"Backup falhou: {e}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 8 ─ PATCHES NO suricata.yaml
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

    # ── 8b ─ Sanitiza e reescreve af-packet inteiro com interface correta ─────
    conteudo = _sanitizar_e_patch_af_packet(conteudo, topo["iface_lan"])

    try:
        yaml_path.write_text(conteudo, encoding="utf-8")
        print_resultado(True, "Patches aplicados no suricata.yaml.")
        return True
    except Exception as e:
        print_resultado(False, f"Erro ao salvar suricata.yaml: {e}")
        return False


def _patch_home_net(conteudo: str, home_net: list) -> str:
    """Substitui (ou insere) HOME_NET no suricata.yaml."""
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
    """
    Garante que jarvis-guard/jg.rules aparece em rule-files.
    As regras ET são gerenciadas pelo suricata-update.
    """
    MARCADOR = "jarvis-guard/jg.rules"
    ENTRADA  = "  - jarvis-guard/jg.rules"

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
    """Garante bloco eve-log com /var/log/suricata/eve.json."""
    if "/var/log/suricata/eve.json" in conteudo:
        return conteudo

    EVE_BLOCK = (
        "\n  # == Jarvis Guard: eve-log ==\n"
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


def _sanitizar_e_patch_af_packet(conteudo: str, interface: str) -> str:
    """
    Reescreve a seção af-packet INTEIRA com apenas a interface escolhida.

    Remove eth0, eth1, default e qualquer outro placeholder que venha
    no suricata.yaml padrão do Debian/Ubuntu. Neutraliza pcap: também.

    Isso garante que o Suricata não tenta capturar em eth0 que não existe,
    o que causava kernel_packets: 0 e o sensor nunca enviava eventos.
    """
    # ── 1) Reescreve af-packet: inteiro com bloco limpo ───────────────────────
    bloco_af = (
        "af-packet:\n"
        "  # == Jarvis Guard ==\n"
        f"  - interface: {interface}\n"
        "    threads: auto\n"
        "    cluster-id: 99\n"
        "    cluster-type: cluster_flow\n"
        "    defrag: yes\n"
    )

    if re.search(r"(?m)^af-packet:", conteudo):
        conteudo = re.sub(
            r"(?m)^af-packet:\n(?:^[ \t].*\n)*",
            bloco_af,
            conteudo,
        )
    else:
        conteudo += f"\n{bloco_af}"

    # ── 2) Neutraliza pcap: (modo de captura alternativo) ─────────────────────
    bloco_pcap = "pcap:\n  - interface: none\n"
    if re.search(r"(?m)^pcap:", conteudo):
        conteudo = re.sub(
            r"(?m)^pcap:\n(?:^[ \t].*\n)*",
            bloco_pcap,
            conteudo,
        )
    else:
        conteudo += f"\n{bloco_pcap}"

    print_resultado(True, f"af-packet configurado → interface: {interface}")
    return conteudo


# ══════════════════════════════════════════════════════════════════════════════
# 9 ─ VALIDAR CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def _testar_suricata(yaml_path: Path) -> tuple:
    """
    Roda suricata -T e verifica erros reais (linhas com prefixo 'E:').
    Warnings (W:) não bloqueiam a instalação.
    """
    linha_texto("Validando configuração com suricata -T ...", C_DIM)
    linha_texto("(isso pode levar alguns segundos)", C_DIM)
    _, out, err = run_cmd(f"suricata -T -c {yaml_path} 2>&1")
    saida = (out + err).strip()

    erros = [
        l.strip()
        for l in saida.split("\n")
        if l.strip().startswith("E:")
    ]

    if not erros:
        warnings = [l.strip() for l in saida.split("\n") if l.strip().startswith("W:")]
        if warnings:
            linha_texto("  Avisos (não impedem o funcionamento):", C_AVISO)
            for w in warnings[:3]:
                linha_texto(f"    {w}", C_DIM)
        return True, "OK"

    linha_texto("  Erros encontrados:", C_ERRO)
    for e in erros[:5]:
        linha_texto(f"    {e}", C_ERRO)
    return False, erros[0]


# ══════════════════════════════════════════════════════════════════════════════
# 10 ─ REINICIAR SERVIÇO
# ══════════════════════════════════════════════════════════════════════════════

def _reiniciar_servico() -> tuple:
    if not cmd_existe("systemctl"):
        return False, (
            "systemd não encontrado — inicie manualmente: "
            "suricata -c /etc/suricata/suricata.yaml -i <iface>"
        )

    linha_texto("Habilitando e reiniciando o serviço Suricata...", C_DIM)
    run_cmd("systemctl enable --now suricata")
    run_cmd("systemctl restart suricata")

    code, out, _ = run_cmd("systemctl is-active suricata")
    status = out.strip()

    if code == 0 and status == "active":
        return True, "active"

    return False, status or "inativo"


# ══════════════════════════════════════════════════════════════════════════════
# 11 ─ CHECAR eve.json
# ══════════════════════════════════════════════════════════════════════════════

def _checar_eve_json() -> tuple:
    if EVE_JSON.exists():
        tam = EVE_JSON.stat().st_size
        return True, f"eve.json encontrado ({tam:,} bytes)"
    return False, (
        "eve.json ainda não existe. Aguarde alguns segundos "
        "e use [9] Diagnóstico para verificar."
    )


# ══════════════════════════════════════════════════════════════════════════════
# FUNÇÕES PÚBLICAS (usadas pelo diagnóstico e pelo menu)
# ══════════════════════════════════════════════════════════════════════════════

def detectar_interfaces() -> list:
    """Retorna nomes das interfaces válidas (sem lo / virtuais)."""
    return [i["nome"] for i in _listar_interfaces_com_ip()]