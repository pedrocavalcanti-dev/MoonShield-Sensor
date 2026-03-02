"""
suricata/instalador.py
Instalador e configurador do Suricata para o Jarvis Guard Sensor.
Deve ser executado como root no Linux (gateway).

Fluxo:
  1  Validar Linux + root
  2  Garantir Suricata (instalar se necessário)
  2b Baixar regras Emerging Threats (ET Open) via suricata-update
  3  Localizar suricata.yaml
  4  Detectar topologia de rede (WAN / LAN / HOME_NET / DNS)
  5  Confirmar topologia com o usuário
  6  Copiar regras JG (sempre sobrescrever)
  7  Backup do suricata.yaml
  8  Aplicar patches (HOME_NET, rule-files, eve-log, af-packet)
  9  Validar com suricata -T  →  restaurar backup se falhar
  10 Habilitar + reiniciar serviço
  11 Verificar eve.json
"""

import os
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

# Interfaces virtuais que devem ser ignoradas na detecção automática
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

    # ── 4 ─ Detectar topologia ────────────────────────────────────────────────
    topo = _detectar_topologia()

    # ── 5 ─ Confirmar topologia com o usuário ─────────────────────────────────
    topo = _confirmar_topologia(topo)
    if topo is None:
        print_resultado(False, "Configuração de topologia cancelada. Abortando.")
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

    # ── Persistir topologia no config.json ───────────────────────────────────
    cfg["suricata_yaml"]     = str(yaml_path)
    cfg["interface_captura"] = topo["iface_lan"]
    cfg["interface_wan"]     = topo["iface_wan"]
    cfg["home_net"]          = topo["home_net"]
    cfg["dns_interno"]       = topo["dns_interno"]
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

    As regras ET Open são gratuitas e cobrem ~40.000 assinaturas de:
      • Malware / C2 conhecidos
      • Scans e exploits
      • DNS/TLS/HTTP suspeitos
      • Botnets, mineradores, etc.

    As regras JG (jarvis-guard) são adicionadas POR CIMA das ET,
    cobrindo comportamentos específicos da rede doméstica/corporativa
    que as ET não detectam (bypass DNS, beaconing, etc.).

    Não falha a instalação se suricata-update não estiver disponível —
    o sensor funciona com apenas as regras JG, só com menos cobertura.
    """
    separador()
    linha_texto("REGRAS EMERGING THREATS (ET Open)", C_DESTAQUE)
    linha_vazia()
    linha_texto("  O Suricata precisa de regras para saber o que é suspeito.", C_DIM)
    linha_texto("  As regras ET Open são gratuitas e cobrem ~40.000 ameaças.", C_DIM)
    linha_texto("  As regras JG do Jarvis Guard serão adicionadas por cima.", C_DIM)
    linha_vazia()

    # ── Garante que suricata-update está instalado ────────────────────────────
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
            code, _, err = run_cmd(cmds_update[mgr])
            if code != 0:
                # Tenta via pip como fallback
                run_cmd("pip3 install suricata-update")

    if not cmd_existe("suricata-update"):
        print_resultado(False, "suricata-update não disponível.")
        linha_texto("  Continuando apenas com regras JG (cobertura reduzida).", C_AVISO)
        linha_texto("  Para instalar manualmente: pip3 install suricata-update", C_DIM)
        linha_vazia()
        return False

    # ── Habilita fonte ET Open (gratuita, sem registro) ───────────────────────
    linha_texto("Habilitando fonte Emerging Threats Open...", C_DIM)
    run_cmd("suricata-update enable-source et/open")

    # ── Baixa e instala as regras ─────────────────────────────────────────────
    linha_texto("Baixando regras ET Open... (pode demorar 1-3 min)", C_AVISO)
    linha_texto("Primeira vez: ~40.000 regras (~15 MB)", C_DIM)
    linha_vazia()

    code, out, err = run_cmd("suricata-update --no-reload 2>&1")

    if code == 0:
        # Extrai estatísticas do output do suricata-update
        total_regras = 0
        for linha in (out + err).split("\n"):
            if "rules added" in linha.lower() or "loaded" in linha.lower():
                import re
                nums = re.findall(r'\d+', linha)
                if nums:
                    total_regras = max(int(n) for n in nums)
                    break

        if total_regras > 0:
            print_resultado(True, f"ET Open instaladas: {total_regras:,} regras.")
        else:
            print_resultado(True, "Regras ET Open baixadas e instaladas.")

        linha_texto("  Fonte: Proofpoint ET Open (gratuita)", C_DIM)
        linha_texto("  Atualização automática: execute suricata-update periodicamente", C_DIM)
        linha_vazia()
        return True
    else:
        saida = (out + err)[:200]
        print_resultado(False, f"suricata-update falhou: {saida}")
        linha_texto("  Continuando apenas com regras JG.", C_AVISO)
        linha_texto("  Tente manualmente: sudo suricata-update", C_DIM)
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
# 4 ─ DETECÇÃO DE TOPOLOGIA
# ══════════════════════════════════════════════════════════════════════════════

def _detectar_topologia() -> dict:
    iface_wan  = _detectar_wan()
    todas      = _listar_interfaces_com_ip()
    home_net   = _extrair_cidrs(todas, excluir_iface=iface_wan)
    iface_lan  = _sugerir_lan(todas, iface_wan)
    dns_intern = _detectar_dns_interno(todas, iface_lan)

    return {
        "iface_wan":    iface_wan,
        "iface_lan":    iface_lan,
        "todas_ifaces": todas,
        "home_net":     home_net,
        "dns_interno":  dns_intern,
    }


def _detectar_wan() -> str:
    _, out, _ = run_cmd("ip route show default")
    tokens = out.split()
    for i, t in enumerate(tokens):
        if t == "dev" and i + 1 < len(tokens):
            return tokens[i + 1]
    return ""


def _listar_interfaces_com_ip() -> list:
    _, out, _ = run_cmd("ip -o -4 addr show")
    ifaces = []
    vistas = set()

    for linha in out.splitlines():
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
            rede    = str(ipaddress.IPv4Network(ip_cidr, strict=False))
        except (ValueError, IndexError):
            continue

        vistas.add(nome)

        estado_path = Path(f"/sys/class/net/{nome}/operstate")
        try:
            estado = estado_path.read_text().strip()
        except Exception:
            estado = "?"

        ifaces.append({"nome": nome, "ip": ip, "cidr": ip_cidr, "rede": rede, "estado": estado})

    return ifaces


def _extrair_cidrs(ifaces: list, excluir_iface: str = "") -> list:
    return [i["rede"] for i in ifaces if i["nome"] != excluir_iface]


def _sugerir_lan(ifaces: list, iface_wan: str) -> str:
    candidatos = [i for i in ifaces if i["nome"] != iface_wan]
    ups = [i for i in candidatos if i["estado"] == "up"]
    if ups:
        return ups[0]["nome"]
    if candidatos:
        return candidatos[0]["nome"]
    return ""


def _detectar_dns_interno(ifaces: list, iface_lan: str) -> str:
    nameservers = []
    try:
        for linha in Path("/etc/resolv.conf").read_text().splitlines():
            linha = linha.strip()
            if linha.startswith("nameserver"):
                partes = linha.split()
                if len(partes) >= 2:
                    nameservers.append(partes[1])
    except Exception:
        pass

    iface_info = next((i for i in ifaces if i["nome"] == iface_lan), None)

    if iface_info and nameservers:
        try:
            rede_lan = ipaddress.IPv4Network(iface_info["cidr"], strict=False)
            for ns in nameservers:
                try:
                    if ipaddress.IPv4Address(ns) in rede_lan:
                        return ns
                except ValueError:
                    pass
        except ValueError:
            pass

    if iface_info:
        return iface_info["ip"]

    return nameservers[0] if nameservers else ""


# ══════════════════════════════════════════════════════════════════════════════
# 5 ─ CONFIRMAR TOPOLOGIA COM O USUÁRIO
# ══════════════════════════════════════════════════════════════════════════════

def _confirmar_topologia(topo: dict) -> dict | None:
    linha_texto("TOPOLOGIA DE REDE DETECTADA", C_TITULO, "centro")
    linha_vazia()

    # ── Exibir interfaces encontradas ────────────────────────────────────────
    if topo["todas_ifaces"]:
        linha_texto("Interfaces de rede encontradas nesta máquina:", C_DESTAQUE)
        linha_vazia()
        for iface in topo["todas_ifaces"]:
            marcador = ""
            if iface["nome"] == topo["iface_wan"]:
                marcador = "  ← WAN  (saída para internet — detectada pela rota padrão)"
            elif iface["nome"] == topo["iface_lan"]:
                marcador = "  ← LAN  (sugerida para captura)"
            linha_texto(
                f"  {iface['nome']:<12} {iface['cidr']:<20} [{iface['estado']}]{marcador}",
                C_DIM,
            )
        linha_vazia()
    else:
        linha_texto("Nenhuma interface com IP detectada.", C_AVISO)
        linha_vazia()

    linha_texto("COMO FUNCIONA O MONITORAMENTO:", C_DESTAQUE)
    linha_texto("  O Suricata vai ficar 'escutando' o tráfego de rede em modo passivo.", C_DIM)
    linha_texto("  Ele NÃO bloqueia nada — apenas analisa e gera alertas.", C_DIM)
    linha_texto("  Você configura UMA interface interna (LAN) para captura.", C_DIM)
    linha_texto("  Todo tráfego dos dispositivos da rede passa por ela.", C_DIM)
    linha_vazia()
    linha_texto("  Por que não monitorar a WAN também?", C_AVISO)
    linha_texto("  Monitorar WAN + LAN geraria eventos duplicados (mesmo pacote aparece 2x).", C_DIM)
    linha_texto("  Na LAN você já vê tudo que entra e sai, com IPs internos legíveis.", C_DIM)
    linha_vazia()
    separador()

    # ── PASSO 1: WAN ─────────────────────────────────────────────────────────
    linha_texto("PASSO 1 de 4 — Interface WAN", C_DESTAQUE)
    linha_vazia()
    linha_texto("  O que é: a interface conectada ao roteador / internet.", C_DIM)
    linha_texto("  Detectamos automaticamente pela rota padrão do sistema.", C_DIM)
    linha_texto("  O Suricata NÃO vai monitorar esta interface.", C_DIM)
    linha_texto("  Ela é registrada apenas para documentação da topologia.", C_DIM)
    linha_vazia()
    wan = input_campo("Interface WAN", topo["iface_wan"] or "")
    topo["iface_wan"] = wan.strip()
    linha_vazia()

    # ── PASSO 2: LAN (captura) ────────────────────────────────────────────────
    linha_texto("PASSO 2 de 4 — Interface de Captura (LAN)", C_DESTAQUE)
    linha_vazia()
    linha_texto("  O que é: a interface conectada à sua rede interna.", C_DIM)
    linha_texto("  É AQUI que o Suricata vai monitorar o tráfego.", C_DIM)
    linha_texto("  Exemplos comuns: enp0s3, eth0, ens18", C_DIM)
    linha_vazia()
    linha_texto("  ATENÇÃO: se errar esta interface, o Suricata não", C_AVISO)
    linha_texto("  vai capturar nenhum pacote e o eve.json ficará vazio.", C_AVISO)
    linha_vazia()
    lan = input_campo("Interface de captura (LAN)", topo["iface_lan"] or "")
    if not lan.strip():
        linha_texto("Interface de captura é obrigatória. Abortando.", C_ERRO)
        return None
    topo["iface_lan"] = lan.strip()
    linha_vazia()

    # ── PASSO 3: HOME_NET ─────────────────────────────────────────────────────
    linha_texto("PASSO 3 de 4 — HOME_NET (redes internas)", C_DESTAQUE)
    linha_vazia()
    linha_texto("  O que é: os CIDRs da sua rede interna.", C_DIM)
    linha_texto("  O Suricata usa isso para saber quais IPs são 'seus'", C_DIM)
    linha_texto("  e quais são externos — isso afeta quais alertas disparam.", C_DIM)
    linha_vazia()
    linha_texto("  Exemplos:", C_DIM)
    linha_texto("    192.168.1.0/24   → rede doméstica comum", C_DIM)
    linha_texto("    10.0.0.0/8       → rede corporativa ampla", C_DIM)
    linha_texto("    192.168.1.0/24,10.10.0.0/16  → múltiplas redes", C_DIM)
    linha_vazia()
    home_padrao = ",".join(topo["home_net"]) if topo["home_net"] else "192.168.0.0/16"
    home_str    = input_campo("HOME_NET", home_padrao)
    topo["home_net"] = [c.strip() for c in home_str.split(",") if c.strip()]
    linha_vazia()

    # ── PASSO 4: DNS interno ──────────────────────────────────────────────────
    linha_texto("PASSO 4 de 4 — DNS Interno", C_DESTAQUE)
    linha_vazia()
    linha_texto("  O que é: o IP do servidor DNS que seus dispositivos usam.", C_DIM)
    linha_texto("  Pode ser um Pi-hole, AdGuard Home, ou o próprio roteador.", C_DIM)
    linha_vazia()
    linha_texto("  Para que serve: o Jarvis Guard tem uma regra que detecta", C_DIM)
    linha_texto("  dispositivos ignorando seu DNS interno (bypass DNS).", C_DIM)
    linha_texto("  Se um aparelho consultar 8.8.8.8 em vez do seu DNS,", C_DIM)
    linha_texto("  isso gera um alerta.", C_DIM)
    linha_vazia()
    linha_texto("  Se não tiver DNS interno, pressione Enter para deixar vazio.", C_DIM)
    linha_vazia()
    dns = input_campo("DNS interno", topo["dns_interno"] or "")
    topo["dns_interno"] = dns.strip()
    linha_vazia()

    # ── Resumo para confirmação ───────────────────────────────────────────────
    separador()
    linha_texto("RESUMO — revise antes de aplicar", C_DESTAQUE)
    linha_vazia()
    linha_texto(f"  WAN (só referência)  : {topo['iface_wan'] or '(não informado)'}", C_DIM)
    linha_texto(f"  Captura (LAN)        : {topo['iface_lan']}", C_OK)
    linha_texto(f"  HOME_NET             : {', '.join(topo['home_net'])}", C_OK)
    linha_texto(f"  DNS interno          : {topo['dns_interno'] or '(não configurado)'}", C_DIM)
    linha_vazia()
    linha_texto("  O que vai acontecer a seguir:", C_AVISO)
    linha_texto("    • Regras JG serão copiadas para o sistema", C_DIM)
    linha_texto("    • suricata.yaml receberá os patches necessários", C_DIM)
    linha_texto("    • A configuração será validada com suricata -T", C_DIM)
    linha_texto("    • O serviço Suricata será reiniciado", C_DIM)
    linha_vazia()

    confirma = input_campo("Confirmar e aplicar? (s/n)", "s")
    if confirma.strip().lower() != "s":
        return None

    return topo


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
    conteudo = _patch_af_packet(conteudo, topo["iface_lan"])

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
    As regras ET já são gerenciadas pelo suricata-update e ficam em
    /var/lib/suricata/rules/ — o suricata-update cuida de registrá-las.
    Aqui só garantimos que as regras JG customizadas estão incluídas.
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


def _patch_af_packet(conteudo: str, interface: str) -> str:
    """
    Garante a interface LAN correta no bloco af-packet.

    BUG CORRIGIDO: a versão anterior ignorava a nova interface se o marcador
    JG já existia no yaml (ex: ao rodar o instalador pela segunda vez com
    interface diferente). Agora sempre atualiza a linha de interface.
    """
    MARCADOR = "# == Jarvis Guard: af-packet =="

    # ── Bloco JG já existe: atualiza apenas a linha da interface ─────────────
    if MARCADOR in conteudo:
        linhas       = conteudo.split("\n")
        nova         = []
        dentro_bloco = False

        for linha in linhas:
            if MARCADOR in linha:
                dentro_bloco = True
                nova.append(linha)
                continue

            if dentro_bloco and linha.strip().startswith("- interface:"):
                indent = len(linha) - len(linha.lstrip())
                nova.append(" " * indent + f"- interface: {interface}")
                dentro_bloco = False
                continue

            nova.append(linha)

        return "\n".join(nova)

    # ── Bloco JG não existe ainda: cria ──────────────────────────────────────
    AF_ENTRY = (
        f"\n  {MARCADOR}\n"
        f"  - interface: {interface}\n"
        f"    cluster-id: 99\n"
        f"    cluster-type: cluster_flow\n"
        f"    defrag: yes\n"
    )

    if "af-packet:" in conteudo:
        linhas = conteudo.split("\n")
        nova   = []
        for linha in linhas:
            nova.append(linha)
            if "af-packet:" in linha:
                nova.append(AF_ENTRY)
        return "\n".join(nova)

    return conteudo + f"\naf-packet:\n{AF_ENTRY}"


# ══════════════════════════════════════════════════════════════════════════════
# 9 ─ VALIDAR CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def _testar_suricata(yaml_path: Path) -> tuple:
    """
    Roda suricata -T e verifica se há erros REAIS (linhas com prefixo 'E:').

    Por que não usar o exit code diretamente:
      O Suricata 7 retorna exit code != 0 quando há arquivos de regra
      referenciados no yaml que não existem. Isso gera apenas 'W:' (warning),
      não 'E:' (error). Tratar esse warning como falha bloquearia a instalação
      mesmo com as regras JG perfeitamente válidas.

    Critério de falha: ao menos uma linha começando com 'E:' no output.
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
            linha_texto("  Avisos encontrados (não impedem o funcionamento):", C_AVISO)
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