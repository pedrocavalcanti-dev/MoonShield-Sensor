"""
relay.py
Gerencia o DHCP Relay (dhcrelay) para encaminhar requests DHCP
das VLANs ao servidor Windows Server (ou qualquer DHCP server).

O dhcrelay fica escutando em todas as subinterfaces VLAN e
encaminha os broadcasts de DHCP para o IP do servidor configurado.
"""

import os
import signal
import re
from .utilitarios import rodar, comando_existe, interface_existe

# Arquivo PID para controlar o processo dhcrelay
_PID_FILE = "/var/run/moonshield-dhcrelay.pid"

# Arquivo de log
_LOG_FILE = "/var/log/moonshield-dhcrelay.log"


# ─────────────────────────────────────────────────────────────────────────────
# Verificação de dependências
# ─────────────────────────────────────────────────────────────────────────────

def dhcrelay_disponivel() -> bool:
    """Verifica se o dhcrelay está instalado."""
    return comando_existe("dhcrelay")


def instrucoes_instalacao() -> str:
    return "sudo apt install isc-dhcp-relay -y"


# ─────────────────────────────────────────────────────────────────────────────
# Iniciar relay
# ─────────────────────────────────────────────────────────────────────────────

def iniciar_relay(dhcp_server: str, ifaces_vlan: list[str]) -> tuple[bool, str]:
    """
    Inicia o dhcrelay nas interfaces VLAN informadas, apontando para dhcp_server.

    Passos:
      1. Valida pré-requisitos
      2. Para instância anterior se existir
      3. Verifica que as interfaces existem no sistema
      4. Inicia dhcrelay em background

    Retorna (True, "") em sucesso ou (False, motivo) em erro.
    """
    if not dhcrelay_disponivel():
        return False, (
            "dhcrelay não encontrado. "
            f"Instale com: {instrucoes_instalacao()}"
        )

    if not dhcp_server:
        return False, "IP do servidor DHCP não configurado."

    if not ifaces_vlan:
        return False, "Nenhuma interface VLAN configurada para relay."

    # Para instância anterior silenciosamente
    parar_relay()

    # Filtra interfaces que realmente existem no sistema
    ifaces_ok = [i for i in ifaces_vlan if interface_existe(i)]
    ifaces_faltando = [i for i in ifaces_vlan if i not in ifaces_ok]

    if not ifaces_ok:
        return False, (
            "Nenhuma subinterface VLAN encontrada no sistema. "
            "Aplique as VLANs antes de iniciar o relay."
        )

    # Monta comando dhcrelay
    # -d: não daemoniza (usamos & + PID manualmente para controle)
    # -4: IPv4
    # -i <iface>: escuta nesta interface
    # <dhcp_server>: encaminha para este IP
    cmd = ["dhcrelay", "-4"]
    for iface in ifaces_ok:
        cmd += ["-i", iface]
    cmd.append(dhcp_server)

    # Garante que o diretório de log existe
    try:
        os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)
    except OSError:
        pass

    # Inicia em background via shell para capturar PID
    ifaces_str = " ".join(f"-i {i}" for i in ifaces_ok)
    shell_cmd = (
        f"dhcrelay -4 {ifaces_str} {dhcp_server} "
        f"> {_LOG_FILE} 2>&1 & echo $!"
    )
    ok, pid_str, err = rodar(shell_cmd, silencioso=True)

    if not ok or not pid_str.strip().isdigit():
        return False, f"Falha ao iniciar dhcrelay: {err or 'PID inválido'}"

    # Salva PID
    try:
        with open(_PID_FILE, "w") as f:
            f.write(pid_str.strip())
    except OSError:
        pass  # Não crítico — apenas perde controle do PID

    aviso = ""
    if ifaces_faltando:
        aviso = f" (interfaces ausentes no sistema: {', '.join(ifaces_faltando)})"

    return True, f"PID {pid_str.strip()}{aviso}"


# ─────────────────────────────────────────────────────────────────────────────
# Parar relay
# ─────────────────────────────────────────────────────────────────────────────

def parar_relay() -> tuple[bool, str]:
    """Para o processo dhcrelay gerenciado pelo MoonShield."""
    pid = _ler_pid()

    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass  # Processo já não existe
        except PermissionError:
            return False, f"Sem permissão para encerrar PID {pid}."
        finally:
            _remover_pid()
        return True, f"Processo {pid} encerrado."

    # Fallback: mata todos os dhcrelay do sistema
    ok, _, _ = rodar(["pkill", "-f", "dhcrelay"], silencioso=True)
    return True, "dhcrelay encerrado (pkill)."


# ─────────────────────────────────────────────────────────────────────────────
# Status
# ─────────────────────────────────────────────────────────────────────────────

def status_relay() -> dict:
    """
    Retorna dict com:
      - ativo (bool)
      - pid (int|None)
      - interfaces (list[str]) — interfaces que o processo está usando
      - servidor (str) — IP do servidor DHCP detectado no processo
    """
    pid = _ler_pid()
    resultado = {
        "ativo":      False,
        "pid":        None,
        "interfaces": [],
        "servidor":   "",
    }

    if pid and _processo_vivo(pid):
        resultado["ativo"] = True
        resultado["pid"]   = pid

        # Lê linha de comando do processo para extrair interfaces e servidor
        ok, cmdline, _ = rodar(f"cat /proc/{pid}/cmdline 2>/dev/null", silencioso=True)
        if ok and cmdline:
            # /proc/PID/cmdline usa \0 como separador
            partes = cmdline.replace("\0", " ").split()
            ifaces = []
            prox_e_iface = False
            for parte in partes:
                if parte == "-i":
                    prox_e_iface = True
                    continue
                if prox_e_iface:
                    ifaces.append(parte)
                    prox_e_iface = False
                    continue
                # Último argumento que parece IP é o servidor
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", parte):
                    resultado["servidor"] = parte

            resultado["interfaces"] = ifaces
    else:
        # PID desatualizado — limpa
        _remover_pid()

        # Verifica se há algum dhcrelay rodando fora do nosso controle
        ok, saida, _ = rodar("pgrep -a dhcrelay", silencioso=True)
        if ok and saida:
            resultado["ativo"] = True
            resultado["pid"]   = None  # PID desconhecido

    return resultado


# ─────────────────────────────────────────────────────────────────────────────
# Helpers internos
# ─────────────────────────────────────────────────────────────────────────────

def _ler_pid() -> int | None:
    try:
        if os.path.exists(_PID_FILE):
            with open(_PID_FILE, "r") as f:
                return int(f.read().strip())
    except (ValueError, OSError):
        pass
    return None


def _remover_pid():
    try:
        if os.path.exists(_PID_FILE):
            os.remove(_PID_FILE)
    except OSError:
        pass


def _processo_vivo(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # Sinal 0 = apenas verifica se processo existe
        return True
    except (ProcessLookupError, PermissionError):
        return False