"""
persistencia.py
Lê e grava a configuração de rede do MoonShield em ms_rede.json.
"""

import json
import os
import shutil
from datetime import datetime

# Caminho base relativo ao próprio arquivo (funciona de qualquer CWD)
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARQUIVO_CONFIG = os.path.join(_BASE, "dados", "ms_rede.json")

CONFIG_PADRAO: dict = {
    "trunk_interface": "enp0s9",
    "wan_interface":   "enp0s8",
    "dhcp_server":     "",
    "vlans":           [],
}


# ─────────────────────────────────────────────────────────────────────────────
# Carregar / Salvar
# ─────────────────────────────────────────────────────────────────────────────

def carregar() -> dict:
    """
    Retorna a configuração atual.
    Se o arquivo não existir ou estiver corrompido, recria com valores padrão.
    """
    if not os.path.exists(ARQUIVO_CONFIG):
        _garantir_pasta()
        salvar(CONFIG_PADRAO.copy())
        return CONFIG_PADRAO.copy()

    try:
        with open(ARQUIVO_CONFIG, "r", encoding="utf-8") as f:
            dados = json.load(f)
        # Garante que todas as chaves padrão existem (migração futura)
        for chave, valor in CONFIG_PADRAO.items():
            dados.setdefault(chave, valor)
        return dados
    except (json.JSONDecodeError, OSError):
        # Arquivo corrompido — faz backup e recria
        _fazer_backup()
        salvar(CONFIG_PADRAO.copy())
        return CONFIG_PADRAO.copy()


def salvar(config: dict) -> bool:
    """Grava a configuração em disco. Retorna True se bem-sucedido."""
    try:
        _garantir_pasta()
        # Escreve em arquivo temporário primeiro para não corromper em caso de falha
        tmp = ARQUIVO_CONFIG + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        shutil.move(tmp, ARQUIVO_CONFIG)
        return True
    except OSError as e:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Operações em VLANs
# ─────────────────────────────────────────────────────────────────────────────

def listar_vlans() -> list[dict]:
    return carregar().get("vlans", [])


def buscar_vlan(vlan_id: int) -> dict | None:
    return next((v for v in listar_vlans() if v["id"] == vlan_id), None)


def adicionar_vlan(vlan: dict) -> tuple[bool, str]:
    """
    Adiciona uma VLAN à configuração.
    Retorna (True, "") em sucesso ou (False, motivo) em erro.
    """
    config = carregar()
    vlans  = config.get("vlans", [])

    if any(v["id"] == vlan["id"] for v in vlans):
        return False, f"VLAN {vlan['id']} já existe."

    # Valida campos obrigatórios
    for campo in ("id", "nome", "rede", "gateway"):
        if campo not in vlan or not str(vlan[campo]).strip():
            return False, f"Campo obrigatório ausente: {campo}"

    vlans.append(vlan)
    vlans.sort(key=lambda v: v["id"])
    config["vlans"] = vlans
    ok = salvar(config)
    return (True, "") if ok else (False, "Erro ao salvar arquivo de configuração.")


def remover_vlan(vlan_id: int) -> tuple[bool, str]:
    config = carregar()
    vlans  = config.get("vlans", [])
    novas  = [v for v in vlans if v["id"] != vlan_id]

    if len(novas) == len(vlans):
        return False, f"VLAN {vlan_id} não encontrada."

    config["vlans"] = novas
    ok = salvar(config)
    return (True, "") if ok else (False, "Erro ao salvar arquivo de configuração.")


def atualizar_global(chave: str, valor) -> bool:
    """Atualiza uma chave global (trunk_interface, wan_interface, dhcp_server)."""
    config = carregar()
    config[chave] = valor
    return salvar(config)


# ─────────────────────────────────────────────────────────────────────────────
# Internos
# ─────────────────────────────────────────────────────────────────────────────

def _garantir_pasta():
    os.makedirs(os.path.dirname(ARQUIVO_CONFIG), exist_ok=True)


def _fazer_backup():
    """Copia o arquivo corrompido para .bak com timestamp."""
    try:
        ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
        bak = ARQUIVO_CONFIG + f".{ts}.bak"
        shutil.copy2(ARQUIVO_CONFIG, bak)
    except OSError:
        pass