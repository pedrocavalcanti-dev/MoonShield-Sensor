import os
import sys
import subprocess
import shutil
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# ROOT
# ══════════════════════════════════════════════════════════════════════════════

def is_root() -> bool:
    """Verifica se está rodando como root."""
    return os.geteuid() == 0


def exigir_root():
    """Encerra o programa se não for root."""
    if not is_root():
        print("\n  [!] Este recurso precisa ser executado como root.")
        print("      Use: sudo python3 sensor.py\n")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# COMANDOS DE SISTEMA
# ══════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd: str, capturar: bool = True) -> tuple[int, str, str]:
    """
    Executa um comando shell.
    Retorna (returncode, stdout, stderr).
    """
    resultado = subprocess.run(
        cmd,
        shell=True,
        capture_output=capturar,
        text=True,
    )
    return resultado.returncode, resultado.stdout.strip(), resultado.stderr.strip()


def cmd_existe(nome: str) -> bool:
    """Verifica se um binário existe no PATH."""
    return shutil.which(nome) is not None


# ══════════════════════════════════════════════════════════════════════════════
# GERENCIADOR DE PACOTES
# ══════════════════════════════════════════════════════════════════════════════

def detectar_gerenciador_pacote() -> str | None:
    """
    Detecta o gerenciador de pacotes disponível.
    Retorna: 'apt', 'dnf', 'yum', 'pacman' ou None.
    """
    for mgr in ("apt", "dnf", "yum", "pacman"):
        if cmd_existe(mgr):
            return mgr
    return None


def instalar_pacote(pacote: str) -> bool:
    """
    Tenta instalar um pacote usando o gerenciador detectado.
    Retorna True se ok, False se falhou.
    """
    mgr = detectar_gerenciador_pacote()
    if mgr is None:
        return False

    cmds = {
        "apt":    f"apt install -y {pacote}",
        "dnf":    f"dnf install -y {pacote}",
        "yum":    f"yum install -y {pacote}",
        "pacman": f"pacman -S --noconfirm {pacote}",
    }

    code, _, _ = run_cmd(cmds[mgr])
    return code == 0


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS GERAIS
# ══════════════════════════════════════════════════════════════════════════════

def agora() -> str:
    """Retorna hora atual formatada HH:MM:SS."""
    return datetime.now().strftime("%H:%M:%S")


def tamanho_arquivo(caminho: str) -> int:
    """Retorna tamanho do arquivo em bytes, ou 0 se não existir."""
    try:
        return os.path.getsize(caminho)
    except OSError:
        return 0


def servico_ativo(nome: str) -> bool:
    """Verifica se um serviço systemd está ativo."""
    code, _, _ = run_cmd(f"systemctl is-active --quiet {nome}")
    return code == 0
