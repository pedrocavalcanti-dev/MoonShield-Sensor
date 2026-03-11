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
        "Moon_url":    "",
        "sensor_nome":   socket.gethostname(),
        "min_severity":  "4",
        "batch_size":    20,
        "batch_timeout": 5,
        "eve_path":      EVE_PATH,
        "configurado":   False,
    }


def carregar_config() -> dict:
    cfg_path = os.path.normpath(CONFIG_FILE)
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r") as f:
                cfg = json.load(f)
            padrao = config_padrao()
            for k, v in padrao.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
        except Exception:
            pass
    return config_padrao()


def salvar_config(cfg: dict):
    cfg_path = os.path.normpath(CONFIG_FILE)
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
