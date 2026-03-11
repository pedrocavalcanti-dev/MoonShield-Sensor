#!/usr/bin/env python3
# =============================================================================
#
# ███╗   ███╗███████╗      ███████╗███████╗███╗   ██╗███████╗ ██████╗ ██████╗
# ████╗ ████║██╔════╝      ██╔════╝██╔════╝████╗  ██║██╔════╝██╔═══██╗██╔══██╗
# ██╔████╔██║███████╗      ███████╗█████╗  ██╔██╗ ██║███████╗██║   ██║██████╔╝
# ██║╚██╔╝██║╚════██║      ╚════██║██╔══╝  ██║╚██╗██║╚════██║██║   ██║██╔══██╗
# ██║ ╚═╝ ██║███████║      ███████║███████╗██║ ╚████║███████║╚██████╔╝██║  ██║
# ╚═╝     ╚═╝╚══════╝      ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
#
#  MoonShield Sensor — Agent v2.0
#  github.com/pedrocavalcanti-dev/MoonShield-Sensor
#
# =============================================================================

import sys

from nucleo.configuracao  import carregar_config
from nucleo.interface     import wizard, menu_principal, boot_sequence
from nucleo.monitoramento import modo_auto


def main():
    cfg = carregar_config()

    # Modo automático para systemd / headless — sem boot, sem menu
    if "--auto" in sys.argv:
        modo_auto(cfg)
        return

    # Boot sequence animado
    boot_sequence(cfg)

    # Primeira execução → wizard de configuração
    if not cfg.get("configurado"):
        cfg = wizard(cfg)

    # Menu principal
    menu_principal(cfg)


if __name__ == "__main__":
    main()