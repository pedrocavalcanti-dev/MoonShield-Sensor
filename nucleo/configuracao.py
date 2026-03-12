import os
import json
import socket

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════

VERSION     = "2.0.0"
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.json")
EVE_PATH    = "/var/log/suricata/eve.json"

TIPOS_ACEITOS = {"alert", "dns", "http", "tls"}

SEVERIDADE_MAP = {
    "1": "critico",
    "2": "alto",
    "3": "medio",
    "4": "todos",
}

SEVERIDADE_LABEL = {
    "1": "Crítico (só alertas críticos)",
    "2": "Alto (crítico + alto)",
    "3": "Médio (crítico + alto + médio)",
    "4": "Todos (sem filtro)",
}

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def config_padrao() -> dict:
    return {
        # ── Painel MoonShield ─────────────────────────────────────────────────
        "Moon_url":      "",
        "Moon_usuario":  "",
        "Moon_senha":    "",
        "token":         "",

        # ── Sensor ───────────────────────────────────────────────────────────
        "sensor_nome":   socket.gethostname(),
        "min_severity":  "4",
        "batch_size":    20,
        "batch_timeout": 5,
        "eve_path":      EVE_PATH,

        # ── Estado ───────────────────────────────────────────────────────────
        "configurado":   False,   # wizard inicial concluído
        "wizard_ok":     False,   # wizard inicial concluído (alias explícito)
        "suricata_ok":   False,   # Suricata instalado e configurado pelo instalador

        # ── Topologia de rede (preenchido pelo instalador) ────────────────────
        "interface_lan":          "",   # LAN principal — HOME_NET base
        "interface_wan":          "",   # WAN — saída para internet
        "interface_mgmt":         "",   # Gerência/admin — fora do monitoramento
        "interface_captura":      "",   # alias de interface_lan (compatibilidade)
        "interfaces_monitoradas": [],   # interfaces no af-packet do Suricata
        "home_net":               [],   # CIDRs protegidos pelas regras
        "dns_interno":            "",   # IP do DNS interno (padrão: IP da LAN)
        "suricata_yaml":          "",   # caminho do suricata.yaml configurado
    }


def carregar_config() -> dict:
    cfg_path = os.path.normpath(CONFIG_FILE)
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r") as f:
                cfg = json.load(f)
            # Garante que todos os campos do padrão existem
            padrao = config_padrao()
            for k, v in padrao.items():
                if k not in cfg:
                    cfg[k] = v
            # Compatibilidade: wizard_ok espelha configurado
            if cfg.get("configurado") and not cfg.get("wizard_ok"):
                cfg["wizard_ok"] = True
            return cfg
        except Exception:
            pass
    return config_padrao()


def salvar_config(cfg: dict):
    cfg_path = os.path.normpath(CONFIG_FILE)
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)