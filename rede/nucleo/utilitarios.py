"""
utilitarios.py
Funções auxiliares compartilhadas por todos os módulos de rede.
"""

import ipaddress
import re
import subprocess


# ─────────────────────────────────────────────────────────────────────────────
# Execução de comandos
# ─────────────────────────────────────────────────────────────────────────────

def rodar(cmd, silencioso: bool = False) -> tuple[bool, str, str]:
    """
    Executa um comando e retorna (sucesso, stdout, stderr).

    - Se cmd for lista → subprocess sem shell (seguro, sem interpretação do shell).
    - Se cmd for str   → subprocess com shell=True (para pipes etc.).
    Timeout padrão: 20 segundos.
    """
    if not cmd:
        return False, "", "Comando vazio."

    try:
        usa_shell = isinstance(cmd, str)
        r = subprocess.run(
            cmd,
            shell=usa_shell,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Timeout ao executar comando."
    except FileNotFoundError as e:
        return False, "", f"Executável não encontrado: {e}"
    except Exception as e:
        return False, "", str(e)


def comando_existe(nome: str) -> bool:
    """Verifica se um executável está disponível no PATH."""
    if not nome:
        return False
    ok, _, _ = rodar(["which", nome], silencioso=True)
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Validações de rede
# ─────────────────────────────────────────────────────────────────────────────

def validar_ip(ip: str) -> bool:
    """Retorna True se o IP for válido (sem máscara)."""
    if not ip:
        return False
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validar_cidr(cidr: str) -> bool:
    """Retorna True se a rede CIDR for válida (ex: 10.10.10.0/24)."""
    if not cidr:
        return False
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validar_vlan_id(vid: int) -> bool:
    """VLANs válidas: 1–4094."""
    try:
        vid_int = int(vid)
        return 1 <= vid_int <= 4094
    except (ValueError, TypeError):
        return False


def ip_na_rede(ip: str, cidr: str) -> bool:
    """Verifica se o IP pertence à rede CIDR."""
    if not ip or not cidr:
        return False
    try:
        endereco = ipaddress.IPv4Address(ip)
        rede = ipaddress.IPv4Network(cidr, strict=False)
        return endereco in rede
    except ValueError:
        return False


def prefixo_de_cidr(cidr: str) -> str:
    """Extrai o prefixo de uma rede CIDR. Ex: '10.0.0.0/24' → '24'."""
    if not cidr:
        return "24" # Fallback seguro
    return cidr.split("/")[1] if "/" in cidr else "24"


# ─────────────────────────────────────────────────────────────────────────────
# Informações do sistema
# ─────────────────────────────────────────────────────────────────────────────

def listar_interfaces_sistema() -> list[str]:
    """Retorna nomes de interfaces de rede presentes no sistema (sem loopback)."""
    ok, saida, _ = rodar("ip -o link show", silencioso=True)
    if not ok:
        return []
    
    interfaces = []
    for linha in saida.splitlines():
        m = re.match(r"\d+:\s+(\S+):", linha)
        if m:
            nome = m.group(1).rstrip("@")  # remove sufixo @<parent> de VLANs
            if nome != "lo":
                interfaces.append(nome)
    return interfaces


def gateway_padrao() -> str | None:
    """Retorna o gateway padrão atual ou None."""
    ok, saida, _ = rodar(["ip", "route", "show", "default"], silencioso=True)
    if ok and saida:
        m = re.search(r"default via (\S+)", saida)
        if m:
            return m.group(1)
    return None


def ip_da_interface(nome: str) -> str | None:
    """Retorna o primeiro IP (sem máscara) de uma interface ou None."""
    if not nome:
        return None
    ok, saida, _ = rodar(f"ip -o -4 addr show dev {nome} 2>/dev/null", silencioso=True)
    if ok and saida:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", saida)
        if m:
            return m.group(1)
    return None


def interface_existe(nome: str) -> bool:
    """Verifica fisicamente se a interface existe no Linux."""
    if not nome:
        return False
    ok, _, _ = rodar(["ip", "link", "show", nome], silencioso=True)
    return ok