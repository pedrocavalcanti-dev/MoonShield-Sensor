#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  MOONSHIELD  ·  CONFIG NET  v1.0                            ║
║  Configuração de rede, VLANs e roteamento                    ║
║                                                              ║
║  Uso: sudo python3 ms_confignet.py                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys

# Garante que o diretório do script está no path (para imports relativos)
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)


def _verificar_root():
    if os.geteuid() != 0:
        print("\n  [!] Execute como root: sudo python3 ms_confignet.py\n")
        sys.exit(1)


def _verificar_dependencias():
    """Verifica dependências mínimas antes de abrir o painel."""
    faltando = []

    # ip (iproute2) — obrigatório
    if os.system("which ip > /dev/null 2>&1") != 0:
        faltando.append("iproute2 (comando 'ip')")

    # nft — obrigatório para NAT
    if os.system("which nft > /dev/null 2>&1") != 0:
        faltando.append("nftables (comando 'nft') — instale com: apt install nftables")

    if faltando:
        print("\n  [!] Dependências obrigatórias ausentes:")
        for dep in faltando:
            print(f"      - {dep}")
        print()
        sys.exit(1)


def main():
    _verificar_root()
    _verificar_dependencias()

    # Importa apenas após verificações para mensagens de erro limpas
    from rede.interface.interface import menu_principal
    menu_principal()


if __name__ == "__main__":
    main()