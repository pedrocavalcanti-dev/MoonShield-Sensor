#!/usr/bin/env python3
"""
ms_firewall.py
──────────────────────────────────────────────────────────────────────
Entry point do sensor de firewall MoonShield.

Lê eventos do nftables via journald em tempo real e envia para o
painel Django em /firewall/api/ingest/.

Também sincroniza regras: faz poll em /firewall/api/pending-rules/
a cada 30s e aplica via nft quando há regras pendentes.

Reutiliza config.json do ms_sensor.py — mesmas credenciais e URL.
Se já configurado pelo IDS, vai direto ao menu.

Uso:
  sudo venv/bin/python3 ms_firewall.py          # menu interativo
  sudo venv/bin/python3 ms_firewall.py --auto   # modo serviço
──────────────────────────────────────────────────────────────────────
"""

import sys
import time
import threading
import requests

from nucleo.configuracao import carregar_config, salvar_config, VERSION
from nucleo.utilitarios  import is_root, agora
from nucleo.interface    import (
    limpar, boot_sequence, cabecalho, topo, fundo, separador,
    separador_fino, linha_vazia, linha_texto, print_resultado,
    aguardar_enter, input_campo, spinner_inline,
    C_TITULO, C_WHITE, C_DIM, C_OK, C_ERRO, C_AVISO,
    C_MENU_TXT, C_NEON_DIM, C_BORDA, C_NORMAL,
)
from firewall.instalador   import obter_status, instalar_regras
from firewall.interface    import tela_firewall
import firewall.monitoramento as fw_mon
import firewall.sincronizador as fw_sync

# ══════════════════════════════════════════════════════════════════════════════
# BOOT
# ══════════════════════════════════════════════════════════════════════════════

_BOOT_LINES_FW = [
    ("MOONSHIELD FIREWALL SENSOR v{ver}",        "\033[96m\033[1m", 0.04),
    ("Inicializando modulos...",                  "\033[37m\033[2m", 0.03),
    ("[OK] nucleo.configuracao        carregado", "\033[92m\033[1m", 0.02),
    ("[OK] nucleo.interface           pronto",    "\033[92m\033[1m", 0.02),
    ("[OK] firewall.instalador        pronto",    "\033[92m\033[1m", 0.02),
    ("[OK] firewall.analisador        pronto",    "\033[92m\033[1m", 0.02),
    ("[OK] firewall.monitoramento     standby",   "\033[92m\033[1m", 0.02),
    ("[OK] firewall.sincronizador     standby",   "\033[92m\033[1m", 0.02),
    ("Verificando nftables...",                   "\033[37m\033[2m", 0.03),
    ("Conectando ao MOONSHIELD...",               "\033[37m\033[2m", 0.05),
]

def _boot_firewall(cfg: dict):
    limpar()
    print("\033[92m\033[1m")
    print("  ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗     ")
    print("  ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║     ")
    print("  █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║     ")
    print("  ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║     ")
    print("  ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗")
    print("  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝")
    print("\033[0m")
    print()
    for txt, cor, delay in _BOOT_LINES_FW:
        print(f"  {cor}{txt.format(ver=VERSION)}\033[0m")
        time.sleep(delay)
    print()
    blocos = 32
    for i in range(blocos + 1):
        preenchido = "#" * i
        vazio      = "." * (blocos - i)
        pct        = int((i / blocos) * 100)
        print(
            f"\r  \033[37m\033[2mCarregando  [\033[92m\033[1m{preenchido}"
            f"\033[37m\033[2m{vazio}\033[37m\033[2m] \033[97m\033[1m{pct:3d}%",
            end="", flush=True,
        )
        time.sleep(0.015)
    print(f"  \033[92m\033[1m [OK]\033[0m")
    time.sleep(0.25)

# ══════════════════════════════════════════════════════════════════════════════
# STATUS DE CONEXÃO
# ══════════════════════════════════════════════════════════════════════════════

def _status_conexao(cfg: dict) -> tuple:
    if not cfg.get("Moon_url"):
        return "[?] NAO CONFIGURADO", C_AVISO
    try:
        r = requests.get(cfg["Moon_url"] + "/", timeout=2)
        if r.status_code < 500:
            return "[+] ONLINE", C_OK
        return f"[!] HTTP {r.status_code}", C_AVISO
    except Exception:
        return "[-] OFFLINE", C_ERRO

# ══════════════════════════════════════════════════════════════════════════════
# CABEÇALHO FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

def _cabecalho_fw(cfg: dict, verificar: bool = False):
    limpar()
    if verificar:
        status_str, status_cor = spinner_inline(
            "Verificando conexao...",
            _status_conexao, cfg,
        )
    else:
        status_str, status_cor = _status_conexao(cfg)

    fw_status  = obter_status()
    fw_tag     = "[OK]" if fw_status["instalado"] else "[!!]"
    fw_cor     = C_OK   if fw_status["instalado"] else C_AVISO
    fw_persist = " persistente" if fw_status["persistente"] else " sem persistencia"

    topo()
    linha_texto("MOONSHIELD  .  FIREWALL SENSOR", C_TITULO, "centro")
    linha_texto(f"v{VERSION}  -  github.com/pedrocavalcanti-dev", C_DIM, "centro")
    separador()
    linha_texto(f"  Status     {status_str}", status_cor)
    linha_texto(f"  Moon       {cfg['Moon_url'] or '(nao configurado)'}", C_DIM)
    linha_texto(f"  Sensor     {cfg['sensor_nome']}", C_WHITE)
    linha_texto(
        f"  nftables   {fw_tag} {'ativo' + fw_persist if fw_status['instalado'] else 'nao instalado'}",
        fw_cor,
    )
    separador()

# ══════════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL DO FIREWALL
# ══════════════════════════════════════════════════════════════════════════════

def menu_firewall(cfg: dict):
    _primeira_vez = True

    while True:
        _cabecalho_fw(cfg, verificar=_primeira_vez)
        _primeira_vez = False

        fw_status    = obter_status()
        fw_instalado = fw_status["instalado"]
        fw_tag       = "[OK]" if fw_instalado else "[!!] nao instalado"

        usuario_atual = cfg.get("Moon_usuario") or "(nao configurado)"
        tem_senha     = bool(cfg.get("Moon_senha"))
        cred_label    = f"{usuario_atual}  {'[OK]' if tem_senha else '[!!] sem senha'}"

        mon_rodando  = fw_mon.esta_rodando()
        sync_rodando = fw_sync.esta_rodando()

        mon_tag  = "[RODANDO]"  if mon_rodando  else ""
        sync_tag = "[RODANDO]"  if sync_rodando else ""

        linha_texto("  --- Operacao -----------------------------------------------", C_NEON_DIM)
        linha_texto(
            f"  [0]  >>  Instalar regras nftables  {fw_tag}",
            C_MENU_TXT if fw_instalado else C_AVISO,
        )
        linha_texto(
            f"  [1]  >>  Iniciar monitoramento + sync  {mon_tag}",
            C_OK if mon_rodando else C_WHITE,
        )
        linha_vazia()
        linha_texto("  --- Firewall -----------------------------------------------", C_NEON_DIM)
        linha_texto("  [2]  --  Ver status das regras", C_MENU_TXT)
        linha_texto("  [3]  --  Listar regras ativas (nft list)", C_MENU_TXT)
        linha_texto("  [4]  xx  Remover regras", C_AVISO)
        linha_vazia()
        linha_texto("  --- Configuracao -------------------------------------------", C_NEON_DIM)
        linha_texto("  [5]  --  Configurar URL do Moon", C_MENU_TXT)
        linha_texto("  [6]  <>  Testar conexao com Moon", C_MENU_TXT)
        linha_texto("  [7]  <>  Ver configuracao atual", C_MENU_TXT)
        linha_texto(f"  [8]  --  Credenciais  ({cred_label})", C_MENU_TXT)
        linha_vazia()
        linha_texto("  [Q]  xx  Sair", C_DIM)
        linha_vazia()
        fundo()

        print(C_AVISO + "  > Opcao: " + C_WHITE, end="")
        try:
            opcao = input().strip().upper()
        except (KeyboardInterrupt, EOFError):
            opcao = "Q"

        if   opcao == "0": _tela_instalar(cfg)
        elif opcao == "1": _tela_monitoramento(cfg)
        elif opcao == "2": _tela_status(cfg)
        elif opcao == "3": _tela_listar(cfg)
        elif opcao == "4": _tela_remover(cfg)
        elif opcao == "5": cfg = _tela_config_url(cfg)
        elif opcao == "6": _tela_testar_conexao(cfg)
        elif opcao == "7": _tela_ver_config(cfg)
        elif opcao == "8": cfg = _tela_credenciais(cfg)
        elif opcao == "Q":
            limpar()
            print(C_DIM + "\n  MOONSHIELD Firewall Sensor encerrado.\n")
            sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
# TELA DE MONITORAMENTO + SINCRONIZADOR
# ══════════════════════════════════════════════════════════════════════════════

_session      = requests.Session()
_session_lock = threading.Lock()
_stop_event   = None


def _tela_monitoramento(cfg: dict):
    _cabecalho_fw(cfg)
    linha_texto("  INICIAR MONITORAMENTO DE FIREWALL", C_TITULO)
    linha_vazia()

    if not cfg.get("Moon_url"):
        print_resultado(False, "URL do MoonShield nao configurada.")
        aguardar_enter()
        return

    fw_status = obter_status()
    if not fw_status["instalado"]:
        print_resultado(False, "Regras nftables nao instaladas. Use [0] primeiro.")
        aguardar_enter()
        return

    if fw_mon.esta_rodando():
        linha_texto("  Monitoramento ja esta rodando.", C_OK)
        linha_texto("  Pressione Ctrl+C para parar.", C_DIM)
        aguardar_enter()
        return

    # Autentica antes de começar
    usuario = cfg.get("Moon_usuario", "")
    senha   = cfg.get("Moon_senha", "")
    if usuario and senha:
        linha_texto(f"  Autenticando como {usuario}...", C_DIM)
        ok = _autenticar(cfg)
        print_resultado(ok, "Login OK" if ok else "Login falhou — continuando sem autenticacao")
        linha_vazia()

    linha_texto("  Iniciando leitura do journald...", C_DIM)
    linha_texto("  Iniciando sincronizador de regras (poll 30s)...", C_DIM)
    linha_texto("  Ctrl+C para parar.", C_DIM)
    linha_vazia()
    separador()

    global _stop_event
    _stop_event = threading.Event()

    # Inicia monitoramento de logs
    fw_mon.iniciar_monitoramento(cfg, _stop_event, _session, _session_lock)

    # Inicia sincronizador de regras (poll Django → nft)
    fw_sync.iniciar_sincronizador(cfg, _stop_event, _session, _session_lock)

    # Loop de display no terminal
    try:
        while not _stop_event.is_set():
            mon_stats  = fw_mon.obter_stats()
            sync_stats = fw_sync.obter_stats()
            print(
                f"\r  {C_DIM}logs→ vistos:{C_WHITE}{mon_stats['vistos']:>6,}  "
                f"{C_DIM}env:{C_OK}{mon_stats['enviados']:>6,}  "
                f"{C_DIM}err:{C_ERRO}{mon_stats['erros']:>3,}  "
                f"{C_DIM}| regras→ polls:{C_WHITE}{sync_stats['aplicacoes']:>3}  "
                f"{C_DIM}err:{C_ERRO}{sync_stats['erros']:>2}  "
                f"{C_DIM}ultimo:{C_WHITE}{sync_stats['ultimo_apply']:<10}{C_NORMAL}",
                end="", flush=True,
            )
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        if _stop_event:
            _stop_event.set()
        fw_mon.parar_monitoramento()
        fw_sync.parar_sincronizador()
        print()
        print_resultado(True, "Monitoramento e sincronizador encerrados.")
        aguardar_enter()

# ══════════════════════════════════════════════════════════════════════════════
# TELAS DE CONFIGURAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _tela_instalar(cfg: dict):
    from firewall.interface import _tela_instalar as _fw_instalar
    _fw_instalar(cfg)

def _tela_status(cfg: dict):
    from firewall.interface import _tela_status as _fw_status
    _fw_status(cfg)

def _tela_listar(cfg: dict):
    from firewall.interface import _tela_listar as _fw_listar
    _fw_listar(cfg)

def _tela_remover(cfg: dict):
    from firewall.interface import _tela_remover as _fw_remover
    _fw_remover(cfg)

def _tela_config_url(cfg: dict) -> dict:
    from nucleo.interface import tela_config_ip
    return tela_config_ip(cfg)

def _tela_testar_conexao(cfg: dict):
    from nucleo.interface import tela_testar_conexao
    tela_testar_conexao(cfg)

def _tela_ver_config(cfg: dict):
    from nucleo.interface import tela_ver_config
    tela_ver_config(cfg)

def _tela_credenciais(cfg: dict) -> dict:
    from nucleo.interface import tela_config_credenciais
    return tela_config_credenciais(cfg)

# ══════════════════════════════════════════════════════════════════════════════
# AUTENTICAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def _autenticar(cfg: dict) -> bool:
    usuario = cfg.get("Moon_usuario", "")
    senha   = cfg.get("Moon_senha", "")
    if not usuario or not senha:
        return True
    login_url = cfg["Moon_url"].rstrip("/") + "/auth/login/"
    try:
        with _session_lock:
            r    = _session.get(login_url, timeout=5)
            csrf = _session.cookies.get("csrftoken", "")
            if not csrf:
                import re
                m    = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
                csrf = m.group(1) if m else ""
            r2 = _session.post(
                login_url,
                data={"username": usuario, "password": senha,
                      "csrfmiddlewaretoken": csrf},
                headers={"Referer": login_url},
                timeout=5, allow_redirects=True,
            )
            return "/auth/login/" not in r2.url and r2.status_code == 200
    except Exception:
        return False

# ══════════════════════════════════════════════════════════════════════════════
# MODO --auto  (serviço systemd)
# ══════════════════════════════════════════════════════════════════════════════

def modo_auto(cfg: dict):
    print(f"[{agora()}] MoonShield Firewall Sensor v{VERSION} — modo automatico")
    print(f"[{agora()}] MoonShield : {cfg['Moon_url']}")
    print(f"[{agora()}] Sensor     : {cfg['sensor_nome']}")

    if not cfg.get("Moon_url"):
        print(f"[{agora()}] ERRO: URL nao configurada."); sys.exit(1)

    fw_status = obter_status()
    if not fw_status["instalado"]:
        print(f"[{agora()}] ERRO: regras nftables nao instaladas.")
        print(f"[{agora()}] Execute: sudo venv/bin/python3 ms_firewall.py")
        print(f"[{agora()}] Use a opcao [0] para instalar as regras.")
        sys.exit(1)

    if cfg.get("Moon_usuario") and cfg.get("Moon_senha"):
        print(f"[{agora()}] Autenticando como {cfg['Moon_usuario']}...")
        ok = _autenticar(cfg)
        print(f"[{agora()}] Login {'OK' if ok else 'FALHOU'}")

    stop = threading.Event()

    # Inicia monitoramento de logs
    fw_mon.iniciar_monitoramento(cfg, stop, _session, _session_lock)
    print(f"[{agora()}] Monitoramento de logs iniciado.")

    # Inicia sincronizador de regras
    fw_sync.iniciar_sincronizador(cfg, stop, _session, _session_lock)
    print(f"[{agora()}] Sincronizador de regras iniciado (poll 30s).")
    print(f"[{agora()}] Ctrl+C para parar.")

    def _log_stats():
        while True:
            time.sleep(60)
            m = fw_mon.obter_stats()
            s = fw_sync.obter_stats()
            print(
                f"[{agora()}] logs | vistos={m['vistos']} enviados={m['enviados']} erros={m['erros']} | "
                f"sync | aplicacoes={s['aplicacoes']} erros={s['erros']} ultimo={s['ultimo_apply']}",
                flush=True,
            )
    threading.Thread(target=_log_stats, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()
        fw_mon.parar_monitoramento()
        fw_sync.parar_sincronizador()
        print(f"\n[{agora()}] Encerrado.")
        sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not is_root():
        print("\n  [!] Execute como root: sudo venv/bin/python3 ms_firewall.py\n")
        sys.exit(1)

    cfg = carregar_config()

    if "--auto" in sys.argv:
        modo_auto(cfg)
        return

    _boot_firewall(cfg)

    if not cfg.get("configurado") and not cfg.get("wizard_ok"):
        from nucleo.interface import wizard
        cfg = wizard(cfg)

    menu_firewall(cfg)


if __name__ == "__main__":
    main()