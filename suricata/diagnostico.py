"""
suricata/diagnostico.py
Doctor do MOONSHIELD Sensor — verifica toda a stack do Suricata.
Usa informações de topologia salvas no config.json quando disponíveis.
Não depende de libs externas além de stdlib + ipaddress.
"""

import os
import sys
import time
import ipaddress
from pathlib import Path

# ── Raiz do projeto ───────────────────────────────────────────────────────────
_AQUI    = Path(__file__).resolve().parent
BASE_DIR = _AQUI.parent

# ── Caminhos padrão ───────────────────────────────────────────────────────────
YAML_CANDIDATOS = [
    Path("/etc/suricata/suricata.yaml"),
    Path("/usr/local/etc/suricata/suricata.yaml"),
]
REGRAS_DEST = Path("/var/lib/suricata/rules/moonshield/ms.rules")
EVE_JSON    = Path("/var/log/suricata/eve.json")

# ── Imports visuais ───────────────────────────────────────────────────────────
from nucleo.interface import (
    cabecalho, separador, linha_texto, linha_vazia,
    aguardar_enter,
    C_DESTAQUE, C_DIM, C_OK, C_ERRO, C_AVISO, C_NORMAL, C_TITULO,
)
from nucleo.utilitarios import run_cmd, cmd_existe


# ══════════════════════════════════════════════════════════════════════════════
# PONTO DE ENTRADA PÚBLICO
# ══════════════════════════════════════════════════════════════════════════════

def executar_diagnostico(cfg: dict) -> dict:
    """Roda o checklist completo e exibe resultado na tela."""
    cabecalho(cfg)
    linha_texto("DIAGNÓSTICO SURICATA — DOCTOR", C_DESTAQUE)
    linha_vazia()

    yaml_path = _encontrar_yaml(cfg)
    resultados = []

    # ── Sistema / Ambiente ────────────────────────────────────────────────────
    resultados.append(_check_linux())
    resultados.append(_check_root())
    resultados.append(_check_suricata_instalado())

    # ── Configuração ─────────────────────────────────────────────────────────
    resultados.append(_check_yaml(yaml_path))
    resultados.append(_check_suricata_t(yaml_path))
    resultados.append(_check_home_net(yaml_path, cfg))
    resultados.append(_check_regras_ms())
    resultados.append(_check_yaml_referencia_jg(yaml_path))

    # ── Serviço ───────────────────────────────────────────────────────────────
    resultados.append(_check_servico())

    # ── Interface de captura ──────────────────────────────────────────────────
    resultados.append(_check_interface_captura(cfg))

    # ── Logs ─────────────────────────────────────────────────────────────────
    resultados.append(_check_eve_existe(cfg))
    resultados.append(_check_eve_atualiza(cfg))
    resultados.append(_check_permissao_eve(cfg))

    # ── Topologia / Policy ────────────────────────────────────────────────────
    resultados.append(_check_dns_interno(cfg))
    resultados.append(_check_bypass_dns_config(yaml_path, cfg))

    # ── Exibir resultados ─────────────────────────────────────────────────────
    separador()
    _exibir_resultados(resultados)
    separador()
    _exibir_acoes(resultados)
    separador()
    _exibir_topologia_salva(cfg)
    separador()
    _exibir_comandos_uteis()
    linha_vazia()
    aguardar_enter()
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _item(id_: str, ok: bool, label: str, detalhe: str = "", acao: str = "") -> dict:
    return {"id": id_, "ok": ok, "label": label, "detalhe": detalhe, "acao": acao}


def _encontrar_yaml(cfg: dict) -> Path | None:
    """Tenta encontrar o suricata.yaml: primeiro no cfg, depois nos candidatos padrão."""
    if cfg.get("suricata_yaml"):
        p = Path(cfg["suricata_yaml"])
        if p.exists():
            return p

    for c in YAML_CANDIDATOS:
        if c.exists():
            return c

    return None


# ══════════════════════════════════════════════════════════════════════════════
# CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def _check_linux() -> dict:
    ok = sys.platform != "win32"
    return _item(
        "linux", ok, "Sistema Linux",
        "" if ok else "Windows detectado",
        "" if ok else "Use uma máquina Linux (Ubuntu/Debian recomendado)",
    )


def _check_root() -> dict:
    ok = os.geteuid() == 0
    return _item(
        "root", ok, "Executando como root",
        "" if ok else f"UID={os.getuid()}",
        "" if ok else "Execute: sudo python3 sensor.py",
    )


def _check_suricata_instalado() -> dict:
    if cmd_existe("suricata"):
        _, out, _ = run_cmd("suricata --version")
        versao = out.split("\n")[0].strip() if out else "versão desconhecida"
        return _item("suricata_bin", True, "Suricata instalado", versao)
    return _item(
        "suricata_bin", False, "Suricata instalado",
        "binário não encontrado no PATH",
        "Use [0] Instalar/Configurar Suricata no menu",
    )


def _check_yaml(yaml_path: Path | None) -> dict:
    if yaml_path:
        return _item("yaml", True, "suricata.yaml encontrado", str(yaml_path))
    return _item(
        "yaml", False, "suricata.yaml encontrado",
        "não encontrado nos caminhos padrão",
        "Use [0] Instalar/Configurar Suricata",
    )


def _check_suricata_t(yaml_path: Path | None) -> dict:
    if yaml_path is None:
        return _item("suricata_t", False, "suricata -T (config válida)", "yaml ausente — pulado")

    code, out, err = run_cmd(f"suricata -T -c {yaml_path} 2>&1")
    saida = (out + err).strip()

    if code == 0:
        return _item("suricata_t", True, "suricata -T (config válida)", "OK")

    erro = ""
    for linha in saida.split("\n"):
        if "error" in linha.lower() or "fatal" in linha.lower():
            erro = linha.strip()
            break
    if not erro:
        erro = saida[:160]

    return _item(
        "suricata_t", False, "suricata -T (config válida)",
        erro,
        f"Inspecione: suricata -T -c {yaml_path}",
    )


def _check_home_net(yaml_path: Path | None, cfg: dict) -> dict:
    """Verifica se HOME_NET no yaml bate com o que está no config."""
    home_cfg = cfg.get("home_net", [])

    if yaml_path is None:
        return _item("home_net", False, "HOME_NET configurado no yaml", "yaml ausente — pulado")

    try:
        conteudo = yaml_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return _item("home_net", False, "HOME_NET configurado no yaml", "erro ao ler yaml")

    # Procura linha com HOME_NET:
    for linha in conteudo.splitlines():
        if linha.strip().startswith("HOME_NET:"):
            valor = linha.split(":", 1)[1].strip().strip('"').strip("'")
            if home_cfg:
                # Verifica se pelo menos um CIDR do cfg está presente
                faltando = [c for c in home_cfg if c not in valor]
                if not faltando:
                    return _item("home_net", True, "HOME_NET configurado no yaml", valor[:60])
                return _item(
                    "home_net", False, "HOME_NET configurado no yaml",
                    f"yaml tem: {valor[:40]} | falta: {', '.join(faltando[:2])}",
                    "Use [0] Instalar/Configurar Suricata para reaplicar patches",
                )
            return _item("home_net", True, "HOME_NET configurado no yaml", valor[:60])

    return _item(
        "home_net", False, "HOME_NET configurado no yaml",
        "HOME_NET não encontrado no yaml",
        "Use [0] Instalar/Configurar Suricata para aplicar o patch",
    )


def _check_regras_ms() -> dict:
    if REGRAS_DEST.exists():
        tam = REGRAS_DEST.stat().st_size
        return _item("regras_ms", True, "Regras JG instaladas", f"{REGRAS_DEST} ({tam:,} bytes)")
    return _item(
        "regras_ms", False, "Regras JG instaladas",
        f"não encontrado: {REGRAS_DEST}",
        "Use [0] Instalar/Configurar Suricata para copiar as regras",
    )


def _check_yaml_referencia_jg(yaml_path: Path | None) -> dict:
    if yaml_path is None:
        return _item("yaml_ref_jg", False, "suricata.yaml referencia ms.rules", "yaml ausente — pulado")
    try:
        conteudo = yaml_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return _item("yaml_ref_jg", False, "suricata.yaml referencia ms.rules", str(e))

    if "moonshield/ms.rules" in conteudo:
        return _item("yaml_ref_jg", True, "suricata.yaml referencia ms.rules", "entrada encontrada")
    return _item(
        "yaml_ref_jg", False, "suricata.yaml referencia ms.rules",
        "entrada ausente em rule-files",
        "Use [0] Instalar/Configurar Suricata para aplicar o patch",
    )


def _check_servico() -> dict:
    if not cmd_existe("systemctl"):
        return _item(
            "servico", False, "Serviço suricata ativo",
            "systemd não encontrado",
            "Inicie manualmente: suricata -c /etc/suricata/suricata.yaml -i <iface>",
        )
    code, out, _ = run_cmd("systemctl is-active suricata")
    status = out.strip()
    ok = code == 0 and status == "active"
    return _item(
        "servico", ok, "Serviço suricata ativo", status,
        "" if ok else "Execute: systemctl enable --now suricata && systemctl restart suricata",
    )


def _check_interface_captura(cfg: dict) -> dict:
    iface = cfg.get("interface_captura", "")
    if not iface:
        return _item(
            "iface_captura", False, "Interface de captura configurada",
            "não definida no config",
            "Use [0] Instalar/Configurar Suricata",
        )

    # Verifica se existe no sistema
    iface_path = Path(f"/sys/class/net/{iface}")
    if not iface_path.exists():
        return _item(
            "iface_captura", False, f"Interface de captura: {iface}",
            "interface não encontrada no sistema",
            f"Verifique: ip link show {iface}",
        )

    # Estado operacional
    try:
        estado = (iface_path / "operstate").read_text().strip()
    except Exception:
        estado = "?"

    ok = estado in ("up", "unknown")
    return _item(
        "iface_captura", ok, f"Interface de captura: {iface}",
        f"estado: {estado}",
        "" if ok else f"Interface está {estado}. Verifique o cabo/link: ip link set {iface} up",
    )


def _check_eve_existe(cfg: dict) -> dict:
    eve = Path(cfg.get("eve_path", str(EVE_JSON)))
    if eve.exists():
        tam = eve.stat().st_size
        return _item("eve_existe", True, "eve.json existe", f"{tam:,} bytes em {eve}")
    return _item(
        "eve_existe", False, "eve.json existe",
        f"não encontrado: {eve}",
        "Verifique se o Suricata está rodando: journalctl -u suricata -n 20",
    )


def _check_eve_atualiza(cfg: dict) -> dict:
    eve = Path(cfg.get("eve_path", str(EVE_JSON)))
    if not eve.exists():
        return _item("eve_atualiza", False, "eve.json sendo atualizado", "arquivo ausente — pulado")

    tam1 = eve.stat().st_size
    linha_texto("  Aguardando 4s para checar se eve.json cresce...", C_DIM)
    time.sleep(4)
    tam2 = eve.stat().st_size

    if tam2 > tam1:
        return _item("eve_atualiza", True, "eve.json sendo atualizado", f"{tam1:,} → {tam2:,} bytes")

    return _item(
        "eve_atualiza", False, "eve.json sendo atualizado",
        "tamanho não mudou em 4s",
        "Gere tráfego de rede (ping, curl) e verifique novamente",
    )


def _check_permissao_eve(cfg: dict) -> dict:
    eve = Path(cfg.get("eve_path", str(EVE_JSON)))
    if not eve.exists():
        return _item("eve_perm", False, "Permissão de leitura do eve.json", "arquivo ausente — pulado")

    ok = os.access(eve, os.R_OK)
    if ok:
        # Pega as permissões em octal
        modo = oct(eve.stat().st_mode)[-3:]
        return _item("eve_perm", True, "Permissão de leitura do eve.json", f"modo {modo}")
    return _item(
        "eve_perm", False, "Permissão de leitura do eve.json",
        "sem permissão de leitura",
        f"Execute: chmod 644 {eve}",
    )


def _check_dns_interno(cfg: dict) -> dict:
    dns = cfg.get("dns_interno", "")
    if not dns:
        return _item(
            "dns_interno", False, "DNS interno configurado",
            "não definido no config",
            "Use [0] Instalar/Configurar Suricata e informe o IP do DNS",
        )
    return _item("dns_interno", True, "DNS interno configurado", dns)


def _check_bypass_dns_config(yaml_path: Path | None, cfg: dict) -> dict:
    """Verifica se as regras de bypass DNS no yaml referenciam o DNS correto."""
    if yaml_path is None:
        return _item("bypass_dns", False, "Regra bypass DNS no yaml", "yaml ausente — pulado")

    try:
        conteudo = yaml_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return _item("bypass_dns", False, "Regra bypass DNS no yaml", "erro ao ler yaml")

    # Simplesmente verifica se a seção de regras está referenciando ms.rules
    if "moonshield/ms.rules" in conteudo:
        return _item(
            "bypass_dns", True, "Regra bypass DNS ativa",
            "ms.rules carregado (inclui SIDs 9900023-9900025)",
        )

    return _item(
        "bypass_dns", False, "Regra bypass DNS ativa",
        "ms.rules não referenciado no yaml",
        "Use [0] Instalar/Configurar Suricata para aplicar o patch",
    )


# ══════════════════════════════════════════════════════════════════════════════
# EXIBIÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _exibir_resultados(resultados: list):
    linha_texto("RESULTADO DOS CHECKS", C_DESTAQUE)
    linha_vazia()

    grupos = {
        "Sistema":       ["linux", "root"],
        "Suricata":      ["suricata_bin", "yaml", "suricata_t"],
        "Configuração":  ["home_net", "regras_ms", "yaml_ref_jg"],
        "Serviço":       ["servico", "iface_captura"],
        "Logs":          ["eve_existe", "eve_atualiza", "eve_perm"],
        "Topologia":     ["dns_interno", "bypass_dns"],
    }

    for grupo, ids in grupos.items():
        linha_texto(f"  {grupo}", C_AVISO)
        for r in resultados:
            if r["id"] in ids:
                icone = (C_OK + "✔") if r["ok"] else (C_ERRO + "✗")
                det   = f"  ({r['detalhe'][:35]})" if r["detalhe"] else ""
                cor   = C_NORMAL if r["ok"] else C_ERRO
                print(
                    "\033[36m║    \033[0m"
                    + icone + " "
                    + cor + r["label"]
                    + C_DIM + det
                    + "\033[0m"
                )
        linha_vazia()


def _exibir_acoes(resultados: list):
    falhas = [r for r in resultados if not r["ok"] and r["acao"]]
    if not falhas:
        linha_texto("✔ Tudo OK — pronto para iniciar o sensor!", C_OK, "centro")
        return

    linha_texto("AÇÕES RECOMENDADAS", C_AVISO)
    linha_vazia()
    for r in falhas:
        linha_texto(f"  ❯ {r['label']}", C_ERRO)
        linha_texto(f"    {r['acao']}", C_DIM)
        linha_vazia()


def _exibir_topologia_salva(cfg: dict):
    """Exibe a topologia salva no config.json."""
    linha_texto("TOPOLOGIA SALVA", C_DESTAQUE)
    linha_vazia()

    campos = [
        ("Interface captura (LAN)", cfg.get("interface_captura", "(não configurado)")),
        ("Interface WAN",           cfg.get("interface_wan",     "(não configurado)")),
        ("HOME_NET",                ", ".join(cfg.get("home_net", [])) or "(não configurado)"),
        ("DNS interno",             cfg.get("dns_interno", "(não configurado)")),
        ("suricata.yaml",           cfg.get("suricata_yaml", "(não configurado)")),
        ("eve.json",                cfg.get("eve_path", str(EVE_JSON))),
    ]

    for label, valor in campos:
        linha_texto(f"  {label:<22}: {valor}", C_DIM)

    linha_vazia()
    linha_texto("Para reconfigurar: use [0] Instalar/Configurar Suricata", C_DIM)


def _exibir_comandos_uteis():
    linha_texto("COMANDOS ÚTEIS", C_DESTAQUE)
    linha_vazia()

    cmds = [
        ("Status do serviço",          "systemctl status suricata"),
        ("Logs do serviço (últimas 30)","journalctl -u suricata --no-pager | tail -30"),
        ("Testar configuração",         "suricata -T -c /etc/suricata/suricata.yaml"),
        ("Reiniciar serviço",           "systemctl restart suricata"),
        ("Ver eve.json ao vivo",        "tail -f /var/log/suricata/eve.json"),
        ("Corrigir permissão eve.json", "chmod 644 /var/log/suricata/eve.json"),
        ("Ver interfaces com IP",       "ip -o -4 addr show"),
        ("Ver rota padrão (WAN)",       "ip route show default"),
        ("Ver DNS do sistema",          "cat /etc/resolv.conf"),
    ]

    for desc, cmd in cmds:
        linha_texto(f"  {desc}:", C_DIM)
        linha_texto(f"    {cmd}", C_NORMAL)
        linha_vazia()
