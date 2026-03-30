"""
vlan.py
Gerencia subinterfaces VLAN (802.1Q) no Linux.

Cada VLAN é uma subinterface do tipo:
    enp0s9.10  →  VLAN ID 10 na interface trunk enp0s9
"""

import re
from .utilitarios import rodar, interface_existe, prefixo_de_cidr


# ─────────────────────────────────────────────────────────────────────────────
# Criar
# ─────────────────────────────────────────────────────────────────────────────

def criar_subinterface(trunk: str, vlan_id: int, gateway: str, cidr: str) -> tuple[bool, str]:
    """
    Cria a subinterface VLAN e aplica o IP do gateway.

    Passos:
      1. Garante que a interface trunk está UP
      2. Remove subinterface antiga se existir (evita duplicata)
      3. Cria a subinterface com 'ip link add ... type vlan'
      4. Sobe a subinterface
      5. Aplica o IP do gateway

    Retorna (True, "") em sucesso ou (False, motivo) em erro.
    """
    nome_sub = f"{trunk}.{vlan_id}"
    prefixo  = prefixo_de_cidr(cidr)

    # 1. Trunk deve existir
    if not interface_existe(trunk):
        return False, f"Interface trunk '{trunk}' não encontrada no sistema."

    # 2. Sobe o trunk (idempotente)
    rodar(["ip", "link", "set", trunk, "up"], silencioso=True)

    # 3. Remove subinterface antiga se já existir
    if interface_existe(nome_sub):
        _remover_subinterface_sistema(nome_sub)

    # 4. Cria subinterface
    ok, _, err = rodar([
        "ip", "link", "add",
        "link", trunk,
        "name", nome_sub,
        "type", "vlan",
        "id", str(vlan_id),
    ])
    if not ok:
        return False, f"Erro ao criar {nome_sub}: {err}"

    # 5. Sobe a subinterface
    ok2, _, err2 = rodar(["ip", "link", "set", nome_sub, "up"])
    if not ok2:
        # Tenta limpar antes de retornar erro
        rodar(["ip", "link", "del", nome_sub], silencioso=True)
        return False, f"Erro ao ativar {nome_sub}: {err2}"

    # 6. Aplica IP do gateway
    ok3, _, err3 = rodar(["ip", "addr", "add", f"{gateway}/{prefixo}", "dev", nome_sub])
    if not ok3:
        rodar(["ip", "link", "del", nome_sub], silencioso=True)
        return False, f"Erro ao aplicar IP {gateway}/{prefixo} em {nome_sub}: {err3}"

    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Remover
# ─────────────────────────────────────────────────────────────────────────────

def remover_subinterface(trunk: str, vlan_id: int) -> tuple[bool, str]:
    """Remove a subinterface VLAN do sistema."""
    nome_sub = f"{trunk}.{vlan_id}"

    if not interface_existe(nome_sub):
        return True, ""  # Já não existe — considera sucesso

    ok, motivo = _remover_subinterface_sistema(nome_sub)
    return ok, motivo


def _remover_subinterface_sistema(nome_sub: str) -> tuple[bool, str]:
    """Derruba e remove uma subinterface pelo nome."""
    # Limpa IPs e rotas
    rodar(["ip", "addr", "flush", "dev", nome_sub], silencioso=True)
    rodar(["ip", "link", "set", nome_sub, "down"], silencioso=True)

    ok, _, err = rodar(["ip", "link", "del", nome_sub])
    if not ok:
        return False, f"Erro ao remover {nome_sub}: {err}"
    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Listar / Status
# ─────────────────────────────────────────────────────────────────────────────

def listar_subinterfaces_ativas(trunk: str) -> list[dict]:
    """
    Retorna subinterfaces VLAN ativas para a interface trunk informada.
    Cada item: {"nome": "enp0s9.10", "vlan_id": 10, "ip": "10.10.10.1", "estado": "UP"}
    """
    resultado = []
    
    # Se não houver trunk definido, retorna vazio para não quebrar a tela de status
    if not trunk:
        return resultado

    ok, saida, _ = rodar("ip -o link show type vlan", silencioso=True)
    if not ok or not saida:
        return resultado

    for linha in saida.splitlines():
        # ex: "5: enp0s9.10@enp0s9: <...> ..."
        m = re.match(r"\d+:\s+(\S+)@(\S+):", linha)
        if not m:
            continue

        nome_sub  = m.group(1)
        pai       = m.group(2)

        if pai != trunk:
            continue

        # Extrai VLAN ID do nome (enp0s9.10 → 10)
        partes = nome_sub.rsplit(".", 1)
        if len(partes) != 2 or not partes[1].isdigit():
            continue
        vlan_id = int(partes[1])

        estado = "UP" if "UP" in linha and "LOWER_UP" in linha else "DOWN"

        # IP
        ok2, s2, _ = rodar(
            f"ip -o -4 addr show dev {nome_sub} 2>/dev/null", silencioso=True
        )
        ip = "—"
        if ok2 and s2:
            m2 = re.search(r"inet (\S+)", s2)
            if m2:
                ip = m2.group(1)

        resultado.append({
            "nome":    nome_sub,
            "vlan_id": vlan_id,
            "ip":      ip,
            "estado":  estado,
        })

    resultado.sort(key=lambda x: x["vlan_id"])
    return resultado


def subinterface_ativa(trunk: str, vlan_id: int) -> bool:
    """Verifica se a subinterface de uma VLAN está UP no sistema."""
    nome_sub = f"{trunk}.{vlan_id}"
    if not interface_existe(nome_sub):
        return False
    ok, saida, _ = rodar(["ip", "link", "show", nome_sub], silencioso=True)
    return ok and "UP" in saida and "LOWER_UP" in saida


# ─────────────────────────────────────────────────────────────────────────────
# Aplicar todas as VLANs salvas
# ─────────────────────────────────────────────────────────────────────────────

def aplicar_todas(config: dict) -> list[tuple[str, bool, str]]:
    """
    Cria todas as subinterfaces VLAN da configuração.
    Retorna lista de (nome_vlan, sucesso, mensagem).
    """
    # Note que peguei a chave 'trunk' do dicionário principal, 
    # ou de 'interfaces' dependendo de como o JSON foi salvo pelo painel TUI.
    trunk    = config.get("trunk") or config.get("interfaces", {}).get("trunk", "")
    vlans    = config.get("vlans", [])
    resultados = []

    if not trunk:
        return [("N/A", False, "Interface Trunk não definida nas configurações.")]

    for vlan in vlans:
        nome = f"VLAN {vlan['id']} ({vlan.get('nome', 'SemNome')})"
        ok, msg = criar_subinterface(
            trunk   = trunk,
            vlan_id = vlan["id"],
            gateway = vlan["ip"], # Ajustado para pegar 'ip' baseado no que definimos antes
            cidr    = vlan.get("rede", "24"), # Fallback caso não ache 'rede'
        )
        resultados.append((nome, ok, msg))

    return resultados


def remover_todas(config: dict) -> list[tuple[str, bool, str]]:
    """Remove todas as subinterfaces VLAN da configuração."""
    trunk    = config.get("trunk") or config.get("interfaces", {}).get("trunk", "")
    vlans    = config.get("vlans", [])
    resultados = []

    if not trunk:
         return [("N/A", False, "Interface Trunk não definida.")]

    for vlan in vlans:
        nome = f"VLAN {vlan['id']} ({vlan.get('nome', 'SemNome')})"
        ok, msg = remover_subinterface(trunk, vlan["id"])
        resultados.append((nome, ok, msg))

    return resultados