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
       → Usuário escolhe qual é a LAN principal (define HOME_NET base)
       → Pergunta se quer adicionar outras redes ao HOME_NET
       → Todas as interfaces UP são monitoradas no af-packet
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
        print_resultado(False, "Nenhuma interface selecionada. Abortando.")
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

    cfg["suricata_yaml"]          = str(yaml_path)
    cfg["interface_captura"]      = topo["iface_lan"]
    cfg["interface_wan"]          = topo.get("iface_wan", "")
    cfg["interfaces_monitoradas"] = topo.get("todas_monitoradas", [topo["iface_lan"]])
    cfg["home_net"]               = topo["home_net"]
    cfg["dns_interno"]            = topo.get("dns_interno", "")
    cfg["eve_path"]               = str(EVE_JSON)

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
# 4 — ESCOLHER INTERFACES + HOME_NET MULTI-REDE
# ══════════════════════════════════════════════════════════════════════════════

def _escolher_interface() -> dict | None:
    """
    1. Lista todas as interfaces disponíveis
    2. Usuário escolhe qual é a LAN principal
    3. Pergunta se quer adicionar outras redes ao HOME_NET
       (ex: rede Senac, rede de gestão, etc)
    4. Todas as interfaces UP são adicionadas ao af-packet automaticamente
    """
    ifaces    = _listar_interfaces_com_ip_e_rx()
    iface_wan = _detectar_wan()

    if not ifaces:
        print_resultado(False, "Nenhuma interface com IP encontrada.")
        return None

    # ── Exibe tabela ──────────────────────────────────────────────────────────
    _exibir_tabela_interfaces(ifaces, iface_wan)

    # ── Sugere LAN como a interface com mais RX que não seja WAN ─────────────
    candidatos = [f for f in ifaces if f["nome"] != iface_wan and f["estado"] == "up"]
    sugest = str(ifaces.index(max(candidatos, key=lambda f: f["rx_pkts"])) + 1) if candidatos else "1"

    # ── Pergunta 1: qual é a LAN ──────────────────────────────────────────────
    linha_texto("  Escolha qual interface é a sua LAN (rede interna principal).", C_AVISO)
    linha_texto("  Ela define o HOME_NET base e é onde estão seus dispositivos.", C_DIM)
    linha_vazia()

    while True:
        resp = input_campo("Qual é a LAN? (número)", sugest).strip()
        if not resp.isdigit():
            linha_texto("  Digite apenas o número.", C_AVISO)
            continue
        idx = int(resp) - 1
        if 0 <= idx < len(ifaces):
            iface_lan = ifaces[idx]
            break
        linha_texto(f"  Número inválido (1–{len(ifaces)}).", C_AVISO)

    # ── HOME_NET começa com a rede da LAN ─────────────────────────────────────
    home_net = [str(ipaddress.IPv4Network(iface_lan["cidr"], strict=False))]

    # ── Pergunta 2: outras redes para o HOME_NET ──────────────────────────────
    outras_ifaces = [f for f in ifaces if f["nome"] != iface_lan["nome"]]

    if outras_ifaces:
        linha_vazia()
        separador()
        linha_texto("HOME_NET ADICIONAL", C_DESTAQUE)
        linha_vazia()
        linha_texto("  Ataques vindos de outras redes (ex: rede Senac, rede de gestão)", C_DIM)
        linha_texto("  só serão detectados se essas redes estiverem no HOME_NET.", C_DIM)
        linha_vazia()
        linha_texto("  Interfaces disponíveis para adicionar ao HOME_NET:", C_AVISO)
        linha_vazia()

        for i, f in enumerate(outras_ifaces, start=1):
            rede = str(ipaddress.IPv4Network(f["cidr"], strict=False))
            tag  = "← WAN" if f["nome"] == iface_wan else ""
            print(
                "\033[36m║\033[0m  "
                + C_DIM
                + f"  {i}. {f['nome']:<12} {f['cidr']:<20} ({rede}) {tag}"
                + "\033[0m"
            )

        linha_vazia()
        linha_texto("  Digite os números separados por vírgula, ou Enter para pular.", C_DIM)
        linha_texto("  Exemplo: 1,2  (adiciona as duas primeiras)", C_DIM)
        linha_vazia()

        resp2 = input_campo("Quais redes adicionar ao HOME_NET?", "").strip()

        if resp2:
            for parte in resp2.split(","):
                parte = parte.strip()
                if parte.isdigit():
                    idx2 = int(parte) - 1
                    if 0 <= idx2 < len(outras_ifaces):
                        rede_extra = str(ipaddress.IPv4Network(
                            outras_ifaces[idx2]["cidr"], strict=False
                        ))
                        if rede_extra not in home_net:
                            home_net.append(rede_extra)
                            print_resultado(
                                True,
                                f"Adicionado ao HOME_NET: {rede_extra} ({outras_ifaces[idx2]['nome']})"
                            )

    # ── Monta lista de interfaces a monitorar (todas UP) ──────────────────────
    todas_monitoradas = [iface_lan["nome"]]
    for f in ifaces:
        if f["nome"] != iface_lan["nome"] and f["estado"] == "up":
            todas_monitoradas.append(f["nome"])

    dns_intern = iface_lan["ip"]

    # ── Resumo final ──────────────────────────────────────────────────────────
    linha_vazia()
    separador()
    linha_texto("RESUMO FINAL", C_DESTAQUE)
    linha_vazia()
    linha_texto(f"  LAN principal  : {iface_lan['nome']}  ({iface_lan['cidr']})", C_OK)
    linha_vazia()
    linha_texto("  HOME_NET (redes protegidas):", C_AVISO)
    for rede in home_net:
        linha_texto(f"    • {rede}", C_OK)
    linha_vazia()
    linha_texto("  Interfaces monitoradas pelo Suricata:", C_AVISO)
    for nome in todas_monitoradas:
        info = next((f for f in ifaces if f["nome"] == nome), {})
        tag  = ""
        if nome == iface_wan:
            tag = "  ← WAN (internet)"
        elif nome == iface_lan["nome"]:
            tag = "  ← LAN principal"
        linha_texto(f"    • {nome}  {info.get('cidr','')}{tag}", C_DIM)
    linha_vazia()
    linha_texto("  O que vai acontecer:", C_AVISO)
    linha_texto("    • Regras MS copiadas para o sistema", C_DIM)
    linha_texto("    • suricata.yaml reescrito com TODAS as interfaces", C_DIM)
    linha_texto("    • HOME_NET configurado com todas as redes selecionadas", C_DIM)
    linha_texto("    • eth0 e placeholders removidos", C_DIM)
    linha_texto("    • Configuração validada com suricata -T", C_DIM)
    linha_texto("    • Suricata reiniciado", C_DIM)
    linha_vazia()

    confirma = input_campo("Confirmar e aplicar? (s/n)", "s")
    if confirma.strip().lower() != "s":
        return None

    return {
        "iface_lan":         iface_lan["nome"],
        "iface_wan":         iface_wan,
        "home_net":          home_net,
        "dns_interno":       dns_intern,
        "todas_ifaces":      ifaces,
        "todas_monitoradas": todas_monitoradas,
    }


def _exibir_tabela_interfaces(ifaces: list, iface_wan: str):
    linha_texto("INTERFACES DE REDE DISPONÍVEIS", C_TITULO, "centro")
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
            info = "← WAN (internet)"
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
        # Destino 1: /var/lib/suricata/rules/moonshield/
        REGRAS_DEST_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REGRAS_ORIGEM, REGRAS_DEST)
        print_resultado(True, f"Regras MS copiadas → {REGRAS_DEST}")

        # Destino 2: /etc/suricata/rules/moonshield/  (onde o Suricata realmente lê)
        etc_dest_dir = Path("/etc/suricata/rules/moonshield")
        etc_dest_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REGRAS_ORIGEM, etc_dest_dir / "ms.rules")
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
    conteudo = _sanitizar_e_patch_af_packet(conteudo, topo["todas_monitoradas"])

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

    # Múltiplas redes: [10.10.0.0/24,10.53.59.0/24]
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
    Reescreve af-packet com TODAS as interfaces.
    LAN = cluster-id 99, demais incrementam (100, 101...).
    Remove eth0/eth1/default/placeholders originais.
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