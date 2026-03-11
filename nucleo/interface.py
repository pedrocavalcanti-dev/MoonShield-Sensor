import os
import sys
import time
import threading
import requests
from colorama import init, Fore, Style

from nucleo.configuracao import (
    VERSION, SEVERIDADE_MAP, SEVERIDADE_LABEL,
    carregar_config, salvar_config,
)

init(autoreset=True)

# ══════════════════════════════════════════════════════════════════════════════
# PALETA — VERDE NEON SOC
# ══════════════════════════════════════════════════════════════════════════════

C_NEON      = Fore.GREEN  + Style.BRIGHT
C_NEON_DIM  = Fore.GREEN  + Style.BRIGHT
C_CYAN_DIM  = Fore.CYAN
C_YELLOW    = Fore.YELLOW + Style.BRIGHT
C_RED       = Fore.RED    + Style.BRIGHT
C_WHITE     = Fore.WHITE  + Style.BRIGHT
C_DIM       = Fore.WHITE  + Style.DIM

C_TITULO    = Fore.CYAN   + Style.BRIGHT
C_BORDA     = Fore.GREEN  + Style.BRIGHT
C_OK        = Fore.GREEN  + Style.BRIGHT
C_ERRO      = Fore.RED    + Style.BRIGHT
C_AVISO     = Fore.YELLOW + Style.BRIGHT
C_MENU_TXT  = Fore.WHITE
C_DESTAQUE  = Fore.WHITE  + Style.BRIGHT
C_NORMAL    = Style.RESET_ALL

LARGURA = 58

_SPINNER = ["|", "/", "-", "\\"]

# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVOS VISUAIS
# ══════════════════════════════════════════════════════════════════════════════

def limpar():
    os.system("cls" if os.name == "nt" else "clear")

def topo():
    print(C_BORDA + "+" + "=" * (LARGURA - 2) + "+")

def fundo():
    print(C_BORDA + "+" + "=" * (LARGURA - 2) + "+")

def separador():
    print(C_BORDA + "+" + "=" * (LARGURA - 2) + "+")

def separador_fino():
    print(C_BORDA + "+" + "-" * (LARGURA - 2) + "+")

def linha_vazia():
    print(C_BORDA + "|" + " " * (LARGURA - 2) + "|")

def linha_texto(texto: str, cor=C_NORMAL, alinhamento: str = "esquerda", pad: int = 2):
    espaco  = LARGURA - 2 - pad * 2
    if alinhamento == "centro":
        t = texto.center(espaco)
    elif alinhamento == "direita":
        t = texto.rjust(espaco)
    else:
        t = texto.ljust(espaco)
    t_limpo = t[:espaco]
    print(
        C_BORDA + "|" + " " * pad
        + cor + t_limpo
        + C_BORDA + " " * (espaco - len(t_limpo) + pad) + "|"
    )

def print_resultado(ok: bool, msg: str):
    if ok:
        print(C_BORDA + "|  " + C_OK   + "  [OK] " + C_OK   + msg + C_NORMAL)
    else:
        print(C_BORDA + "|  " + C_ERRO + "  [!!] " + C_ERRO + msg + C_NORMAL)

def input_campo(prompt: str, valor_atual: str = "") -> str:
    sufixo = f" [{C_CYAN_DIM}{valor_atual}{C_AVISO}]" if valor_atual else ""
    print(C_BORDA + "|  " + C_AVISO + f"> {prompt}{sufixo}" + C_AVISO + ": " + C_WHITE, end="")
    try:
        val = input().strip()
    except (KeyboardInterrupt, EOFError):
        val = ""
    return val if val else valor_atual

def input_senha(prompt: str) -> str:
    import getpass
    print(C_BORDA + "|  " + C_AVISO + f"> {prompt}: " + C_WHITE, end="", flush=True)
    try:
        val = getpass.getpass("")
    except (KeyboardInterrupt, EOFError):
        val = ""
    return val.strip()

def aguardar_enter(msg: str = "  Pressione Enter para voltar ao menu..."):
    linha_vazia()
    print(C_BORDA + "|" + C_DIM + msg + C_NORMAL)
    fundo()
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass

# ══════════════════════════════════════════════════════════════════════════════
# SPINNER
# ══════════════════════════════════════════════════════════════════════════════

def spinner_inline(mensagem: str, func, *args, **kwargs):
    resultado = [None]
    erro      = [None]

    def _run():
        try:
            resultado[0] = func(*args, **kwargs)
        except Exception as e:
            erro[0] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    idx = 0
    while t.is_alive():
        frame = _SPINNER[idx % len(_SPINNER)]
        print(
            f"\r{C_BORDA}|  {C_NEON}{frame} {C_DIM}{mensagem}   ",
            end="", flush=True,
        )
        idx += 1
        time.sleep(0.08)

    t.join()
    print(f"\r{' ' * (LARGURA + 4)}\r", end="", flush=True)

    if erro[0]:
        raise erro[0]
    return resultado[0]

# ══════════════════════════════════════════════════════════════════════════════
# BOOT SEQUENCE
# ══════════════════════════════════════════════════════════════════════════════

_BANNER = r"""
     ██╗ ██████╗     ███████╗███████╗███╗  ██╗███████╗
     ██║██╔════╝     ██╔════╝██╔════╝████╗ ██║██╔════╝
     ██║██║  ███╗    ███████╗█████╗  ██╔██╗██║███████╗
██   ██║██║   ██║    ╚════██║██╔══╝  ██║╚████║╚════██║
╚█████╔╝╚██████╔╝    ███████║███████╗██║ ╚███║███████║
 ╚════╝  ╚═════╝     ╚══════╝╚══════╝╚═╝  ╚══╝╚══════╝"""

_BOOT_LINES = [
    ("MOONSHIELD SENSOR v{ver}",               C_TITULO,  0.04),
    ("Inicializando modulos...",                  C_DIM,     0.03),
    ("[OK] nucleo.configuracao        carregado", C_NEON,    0.02),
    ("[OK] nucleo.monitoramento       standby",   C_NEON,    0.02),
    ("[OK] suricata.diagnostico       pronto",    C_NEON,    0.02),
    ("[OK] suricata.instalador        pronto",    C_NEON,    0.02),
    ("Verificando eve.json...",                   C_DIM,     0.03),
    ("Conectando ao MOONSHIELD...",             C_DIM,     0.05),
]

def boot_sequence(cfg: dict):
    limpar()
    for linha in _BANNER.strip("\n").split("\n"):
        print(C_NEON + linha.center(LARGURA))
        time.sleep(0.03)
    print()
    for txt, cor, delay in _BOOT_LINES:
        print(f"  {cor}{txt.format(ver=VERSION)}{C_NORMAL}")
        time.sleep(delay)
    print()
    blocos = 32
    for i in range(blocos + 1):
        preenchido = "#" * i
        vazio      = "." * (blocos - i)
        pct        = int((i / blocos) * 100)
        print(
            f"\r  {C_DIM}Carregando  [{C_NEON}{preenchido}{C_DIM}{vazio}{C_DIM}] "
            f"{C_WHITE}{pct:3d}%",
            end="", flush=True,
        )
        time.sleep(0.015)
    print(f"  {C_OK} [OK]{C_NORMAL}")
    time.sleep(0.25)

# ══════════════════════════════════════════════════════════════════════════════
# STATUS DE CONEXÃO
# ══════════════════════════════════════════════════════════════════════════════

def _status_conexao(cfg: dict) -> tuple:
    if not cfg.get("jarvis_url"):
        return "[?] NAO CONFIGURADO", C_AVISO
    try:
        r = requests.get(cfg["jarvis_url"] + "/", timeout=2)
        if r.status_code < 500:
            return "[+] ONLINE", C_OK
        return f"[!] HTTP {r.status_code}", C_AVISO
    except Exception:
        return "[-] OFFLINE", C_ERRO

def _status_conexao_com_spinner(cfg: dict) -> tuple:
    if not cfg.get("jarvis_url"):
        return "[?] NAO CONFIGURADO", C_AVISO
    try:
        r = spinner_inline(
            "Verificando conexao com Jarvis...",
            requests.get, cfg["jarvis_url"] + "/", timeout=2,
        )
        if r.status_code < 500:
            return "[+] ONLINE", C_OK
        return f"[!] HTTP {r.status_code}", C_AVISO
    except Exception:
        return "[-] OFFLINE", C_ERRO

# ══════════════════════════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════════════════════════

def _fazer_login(jarvis_url: str, usuario: str, senha: str) -> tuple[bool, str]:
    session   = requests.Session()
    login_url = jarvis_url.rstrip("/") + "/auth/login/"
    try:
        r    = session.get(login_url, timeout=5)
        csrf = session.cookies.get("csrftoken", "")
        if not csrf:
            import re
            m    = re.search(r'csrfmiddlewaretoken.*?value="([^"]+)"', r.text)
            csrf = m.group(1) if m else ""
        r2 = session.post(
            login_url,
            data={"username": usuario, "password": senha, "csrfmiddlewaretoken": csrf},
            headers={"Referer": login_url},
            timeout=5,
            allow_redirects=True,
        )
        if "/auth/login/" not in r2.url and r2.status_code == 200:
            return True, ""
        if "Usuário ou senha incorretos" in r2.text or "credenciais" in r2.text.lower():
            return False, "Usuario ou senha incorretos."
        if r2.status_code == 200 and "/auth/login/" not in r2.url:
            return True, ""
        return False, f"Login falhou (HTTP {r2.status_code})."
    except requests.exceptions.ConnectionError:
        return False, "Nao foi possivel conectar ao MOONSHIELD."
    except Exception as e:
        return False, f"Erro ao fazer login: {e}"

def _fazer_login_com_spinner(jarvis_url: str, usuario: str, senha: str) -> tuple[bool, str]:
    try:
        return spinner_inline("Autenticando...", _fazer_login, jarvis_url, usuario, senha)
    except Exception as e:
        return False, str(e)

# ══════════════════════════════════════════════════════════════════════════════
# CABEÇALHO
# ══════════════════════════════════════════════════════════════════════════════

def cabecalho(cfg: dict, verificar_conexao: bool = False):
    limpar()
    if verificar_conexao:
        status_str, status_cor = _status_conexao_com_spinner(cfg)
    else:
        status_str, status_cor = _status_conexao(cfg)

    usuario   = cfg.get("jarvis_usuario") or "---"
    tem_senha = bool(cfg.get("jarvis_senha"))

    topo()
    linha_texto("MOONSHIELD  .  SENSOR AGENT", C_TITULO, "centro")
    linha_texto(f"v{VERSION}  -  github.com/pedrocavalcanti-dev", C_DIM, "centro")
    separador()
    linha_texto(f"  Status   {status_str}", status_cor)
    linha_texto(f"  Jarvis   {cfg['jarvis_url'] or '(nao configurado)'}", C_DIM)
    linha_texto(f"  Sensor   {cfg['sensor_nome']}", C_WHITE)
    linha_texto(f"  Eve.json {cfg['eve_path']}", C_DIM)
    linha_texto(
        f"  Auth     {usuario}  {'[OK] autenticado' if tem_senha else '[!!] sem senha'}",
        C_OK if tem_senha else C_AVISO,
    )
    separador()

# ══════════════════════════════════════════════════════════════════════════════
# WIZARD
# ══════════════════════════════════════════════════════════════════════════════

def wizard(cfg: dict) -> dict:
    limpar()
    topo()
    linha_texto("MOONSHIELD --- SETUP INICIAL", C_TITULO, "centro")
    linha_texto("Primeira execucao detectada!", C_AVISO, "centro")
    separador()
    linha_vazia()
    linha_texto("  Vamos configurar o sensor em 4 passos.", C_DIM)
    linha_vazia()

    # ── PASSO 1 — URL ────────────────────────────────────────────────────────
    separador_fino()
    linha_texto("  PASSO 1 / 4  -  URL do MOONSHIELD", C_WHITE)
    linha_texto("  Ex: http://192.168.0.105:8000", C_DIM)
    linha_vazia()

    while True:
        url = input_campo("URL do MOONSHIELD")
        if not url:
            print_resultado(False, "URL obrigatoria.")
            continue
        if not url.startswith("http"):
            url = "http://" + url
        url = url.rstrip("/")
        linha_vazia()
        try:
            r = spinner_inline("Testando conexao...", requests.get, url + "/", timeout=4)
            print_resultado(True, f"Jarvis acessivel  -  HTTP {r.status_code}")
            cfg["jarvis_url"] = url
            break
        except Exception as e:
            print_resultado(False, f"Nao consegui conectar: {e}")
            nova = input_campo("Tentar outro endereco? (s/n)", "s")
            if nova.lower() != "s":
                cfg["jarvis_url"] = url
                break

    linha_vazia()

    # ── PASSO 2 — Login ──────────────────────────────────────────────────────
    separador_fino()
    linha_texto("  PASSO 2 / 4  -  Login no MOONSHIELD", C_WHITE)
    linha_vazia()
    linha_texto("  Use o mesmo usuario e senha do painel web.", C_DIM)
    linha_vazia()

    tentativas = 0
    while True:
        usuario = input_campo("Usuario", cfg.get("jarvis_usuario", ""))
        senha   = input_senha("Senha")
        if not usuario or not senha:
            print_resultado(False, "Usuario e senha sao obrigatorios.")
            continue
        linha_vazia()
        ok, erro = _fazer_login_com_spinner(cfg["jarvis_url"], usuario, senha)
        if ok:
            print_resultado(True, f"Login bem-sucedido!  Ola, {usuario}.")
            cfg["jarvis_usuario"] = usuario
            cfg["jarvis_senha"]   = senha
            break
        else:
            tentativas += 1
            print_resultado(False, erro)
            if tentativas >= 3:
                linha_texto("  3 tentativas falhas. Continuando sem login.", C_AVISO)
                cfg["jarvis_usuario"] = usuario
                cfg["jarvis_senha"]   = ""
                break
            tentar = input_campo("Tentar novamente? (s/n)", "s")
            if tentar.lower() != "s":
                cfg["jarvis_usuario"] = usuario
                cfg["jarvis_senha"]   = ""
                break

    linha_vazia()

    # ── PASSO 3 — Nome ───────────────────────────────────────────────────────
    separador_fino()
    linha_texto("  PASSO 3 / 4  -  Nome do sensor", C_WHITE)
    linha_texto("  Ex: IDS-GATEWAY, SENSOR-LAB-01", C_DIM)
    linha_vazia()
    nome = input_campo("Nome do sensor", cfg["sensor_nome"])
    cfg["sensor_nome"] = nome or cfg["sensor_nome"]
    linha_vazia()

    # ── PASSO 4 — Severidade ─────────────────────────────────────────────────
    separador_fino()
    linha_texto("  PASSO 4 / 4  -  Severidade minima dos alertas", C_WHITE)
    linha_vazia()
    for k, v in SEVERIDADE_LABEL.items():
        linha_texto(f"    [{k}]  {v}", C_MENU_TXT)
    linha_vazia()

    while True:
        sev = input_campo("Escolha (1-4)", cfg["min_severity"])
        if sev in SEVERIDADE_MAP:
            cfg["min_severity"] = sev
            break
        print_resultado(False, "Opcao invalida. Digite 1, 2, 3 ou 4.")

    linha_vazia()
    separador()
    linha_texto("  CONFIGURACAO CONCLUIDA", C_OK, "centro")
    linha_vazia()
    linha_texto(f"  Jarvis   : {cfg['jarvis_url']}", C_DIM)
    linha_texto(f"  Usuario  : {cfg.get('jarvis_usuario', '---')}", C_DIM)
    linha_texto(f"  Sensor   : {cfg['sensor_nome']}", C_DIM)
    linha_texto(f"  Severity : {SEVERIDADE_LABEL[cfg['min_severity']]}", C_DIM)
    linha_vazia()

    cfg["configurado"] = True
    spinner_inline("Salvando config.json...", salvar_config, cfg)
    print_resultado(True, "config.json salvo.")
    aguardar_enter()
    return cfg

# ══════════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def menu_principal(cfg: dict):
    from nucleo.monitoramento import tela_sensor

    _primeira_vez = True

    while True:
        cabecalho(cfg, verificar_conexao=_primeira_vez)
        _primeira_vez = False

        usuario_atual = cfg.get("jarvis_usuario") or "(nao configurado)"
        tem_senha     = bool(cfg.get("jarvis_senha"))
        cred_label    = f"{usuario_atual}  {'[OK]' if tem_senha else '[!!] sem senha'}"

        linha_texto("  --- Operacao -----------------------------------------------", C_NEON_DIM)
        linha_texto("  [0]  >>  Instalar / Configurar Suricata", C_MENU_TXT)
        linha_texto("  [1]  >>  Iniciar sensor", C_WHITE)
        linha_vazia()
        linha_texto("  --- Configuracao -------------------------------------------", C_NEON_DIM)
        linha_texto("  [2]  --  Configurar URL do Jarvis", C_MENU_TXT)
        linha_texto("  [3]  --  Configurar nome do sensor", C_MENU_TXT)
        linha_texto("  [4]  --  Configurar severidade minima", C_MENU_TXT)
        linha_texto("  [5]  --  Configurar caminho do eve.json", C_MENU_TXT)
        linha_texto(f"  [8]  --  Credenciais  ({cred_label})", C_MENU_TXT)
        linha_vazia()
        linha_texto("  --- Diagnostico --------------------------------------------", C_NEON_DIM)
        linha_texto("  [6]  <>  Testar conexao com Jarvis", C_MENU_TXT)
        linha_texto("  [7]  <>  Ver configuracao atual", C_MENU_TXT)
        linha_texto("  [9]  <>  Diagnostico do sistema", C_MENU_TXT)
        linha_vazia()
        linha_texto("  [Q]  xx  Sair", C_DIM)
        linha_vazia()
        fundo()

        print(C_AVISO + "  > Opcao: " + C_WHITE, end="")
        try:
            opcao = input().strip().upper()
        except (KeyboardInterrupt, EOFError):
            opcao = "Q"

        if opcao == "0":
            cfg = tela_instalar_suricata(cfg)
        elif opcao == "1":
            tela_sensor(cfg)
        elif opcao == "2":
            cfg = tela_config_ip(cfg)
        elif opcao == "3":
            cfg = tela_config_nome(cfg)
        elif opcao == "4":
            cfg = tela_config_severidade(cfg)
        elif opcao == "5":
            cfg = tela_config_eve(cfg)
        elif opcao == "6":
            tela_testar_conexao(cfg)
        elif opcao == "7":
            tela_ver_config(cfg)
        elif opcao == "8":
            cfg = tela_config_credenciais(cfg)
        elif opcao == "9":
            cfg = tela_diagnostico(cfg)
        elif opcao == "Q":
            limpar()
            print(C_DIM + "\n  MOONSHIELD Sensor encerrado.\n")
            sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
# TELAS DE CONFIGURAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

def tela_config_ip(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("  CONFIGURAR URL DO MOONSHIELD", C_TITULO)
    linha_texto("  Ex: http://192.168.0.105:8000", C_DIM)
    linha_vazia()
    url = input_campo("Nova URL do MOONSHIELD", cfg["jarvis_url"])
    if url:
        if not url.startswith("http"):
            url = "http://" + url
        url = url.rstrip("/")
        cfg["jarvis_url"] = url
        spinner_inline("Salvando...", salvar_config, cfg)
        print_resultado(True, f"URL salva: {url}")
    else:
        print_resultado(False, "Nenhuma alteracao feita.")
    aguardar_enter()
    return cfg

def tela_config_nome(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("  CONFIGURAR NOME DO SENSOR", C_TITULO)
    linha_vazia()
    nome = input_campo("Novo nome do sensor", cfg["sensor_nome"])
    if nome:
        cfg["sensor_nome"] = nome
        spinner_inline("Salvando...", salvar_config, cfg)
        print_resultado(True, f"Nome salvo: {nome}")
    else:
        print_resultado(False, "Nenhuma alteracao feita.")
    aguardar_enter()
    return cfg

def tela_config_severidade(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("  CONFIGURAR SEVERIDADE MINIMA", C_TITULO)
    linha_vazia()
    for k, v in SEVERIDADE_LABEL.items():
        linha_texto(f"    [{k}]  {v}", C_MENU_TXT)
    linha_vazia()
    sev = input_campo("Escolha (1-4)", cfg["min_severity"])
    if sev in SEVERIDADE_MAP:
        cfg["min_severity"] = sev
        spinner_inline("Salvando...", salvar_config, cfg)
        print_resultado(True, f"Severidade salva: {SEVERIDADE_LABEL[sev]}")
    else:
        print_resultado(False, "Opcao invalida.")
    aguardar_enter()
    return cfg

def tela_config_eve(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("  CONFIGURAR CAMINHO DO EVE.JSON", C_TITULO)
    linha_texto("  Padrao: /var/log/suricata/eve.json", C_DIM)
    linha_vazia()
    caminho = input_campo("Caminho do eve.json", cfg["eve_path"])
    if caminho:
        if os.path.exists(caminho):
            print_resultado(True, "Arquivo encontrado.")
        else:
            print_resultado(False, "Nao encontrado (OK se Suricata ainda nao iniciou).")
        cfg["eve_path"] = caminho
        spinner_inline("Salvando...", salvar_config, cfg)
        print_resultado(True, f"Caminho salvo: {caminho}")
    aguardar_enter()
    return cfg

def tela_testar_conexao(cfg: dict):
    cabecalho(cfg)
    linha_texto("  TESTAR CONEXAO COM MOONSHIELD", C_TITULO)
    linha_vazia()

    if not cfg["jarvis_url"]:
        print_resultado(False, "URL nao configurada.")
        aguardar_enter()
        return

    linha_texto(f"  Alvo: {cfg['jarvis_url']}", C_DIM)
    linha_vazia()

    try:
        t0 = time.time()
        r  = spinner_inline("Testando conectividade...", requests.get,
                            cfg["jarvis_url"] + "/", timeout=5)
        ms = int((time.time() - t0) * 1000)
        print_resultado(True, f"GET /  ->  HTTP {r.status_code}  ({ms}ms)")
    except requests.exceptions.ConnectionError:
        print_resultado(False, "Conexao recusada. Jarvis esta rodando?")
        aguardar_enter()
        return
    except Exception as e:
        print_resultado(False, f"Erro: {e}")
        aguardar_enter()
        return

    linha_vazia()
    usuario = cfg.get("jarvis_usuario", "")
    senha   = cfg.get("jarvis_senha", "")
    if not usuario or not senha:
        print_resultado(False, "Credenciais nao configuradas. Use [8] para configurar.")
    else:
        ok, erro = _fazer_login_com_spinner(cfg["jarvis_url"], usuario, senha)
        if ok:
            print_resultado(True, f"Login OK  -  usuario: {usuario}")
        else:
            print_resultado(False, f"Login falhou: {erro}")

    linha_vazia()
    try:
        payload = {"sensor": cfg["sensor_nome"], "eventos": []}
        def _post():
            return requests.post(
                cfg["jarvis_url"] + "/incidentes/api/ingest/",
                json=payload, timeout=5,
                headers={"X-JG-TOKEN": cfg.get("token", "")},
            )
        r2 = spinner_inline("Testando endpoint /ingest/...", _post)
        if r2.status_code == 200:
            print_resultado(True, "POST /incidentes/api/ingest/  ->  HTTP 200  [OK]")
        elif r2.status_code == 403:
            print_resultado(False, "HTTP 403 -- verifique token ou credenciais.")
        else:
            print_resultado(False, f"HTTP {r2.status_code}  ->  {r2.text[:60]}")
    except Exception as e:
        print_resultado(False, f"Erro no ingest: {e}")

    aguardar_enter()

def tela_ver_config(cfg: dict):
    cabecalho(cfg)
    linha_texto("  CONFIGURACAO ATUAL", C_TITULO)
    linha_vazia()
    linha_texto(f"  Jarvis URL    : {cfg['jarvis_url'] or '(vazio)'}", C_DIM)
    linha_texto(f"  Usuario       : {cfg.get('jarvis_usuario') or '(nao configurado)'}", C_DIM)
    linha_texto(f"  Senha         : {'********' if cfg.get('jarvis_senha') else '(nao configurada)'}", C_DIM)
    linha_texto(f"  Nome sensor   : {cfg['sensor_nome']}", C_WHITE)
    linha_texto(f"  Eve.json      : {cfg['eve_path']}", C_DIM)
    linha_texto(f"  Severidade    : {SEVERIDADE_LABEL.get(cfg['min_severity'], '?')}", C_DIM)
    linha_texto(f"  Batch size    : {cfg['batch_size']} eventos", C_DIM)
    linha_texto(f"  Batch timeout : {cfg['batch_timeout']}s", C_DIM)
    linha_vazia()
    separador_fino()
    linha_vazia()
    if os.path.exists(cfg["eve_path"]):
        from nucleo.utilitarios import tamanho_arquivo
        tam = tamanho_arquivo(cfg["eve_path"])
        print_resultado(True, f"eve.json encontrado  ({tam:,} bytes)")
    else:
        print_resultado(False, "eve.json NAO encontrado no caminho configurado.")
    aguardar_enter()

def tela_config_credenciais(cfg: dict) -> dict:
    cabecalho(cfg)
    linha_texto("  CREDENCIAIS DO MOONSHIELD", C_TITULO)
    linha_vazia()
    linha_texto("  Use o mesmo usuario e senha do painel web.", C_DIM)
    linha_texto("  Credenciais salvas em config.json.", C_DIM)
    linha_vazia()

    usuario_atual = cfg.get("jarvis_usuario", "")
    tem_senha     = bool(cfg.get("jarvis_senha"))
    linha_texto(f"  Usuario atual : {usuario_atual or '(nao configurado)'}", C_WHITE)
    linha_texto(f"  Senha atual   : {'********' if tem_senha else '(nao configurada)'}", C_DIM)
    linha_vazia()

    usuario = input_campo("Novo usuario", usuario_atual)
    if not usuario:
        print_resultado(False, "Nenhuma alteracao feita.")
        aguardar_enter()
        return cfg

    senha = input_senha("Nova senha (Enter = manter atual)")
    if not senha and tem_senha:
        senha = cfg["jarvis_senha"]
        linha_texto("  Mantendo senha atual.", C_DIM)
    if not senha:
        print_resultado(False, "Senha obrigatoria.")
        aguardar_enter()
        return cfg

    linha_vazia()
    ok, erro = _fazer_login_com_spinner(cfg["jarvis_url"], usuario, senha)
    if ok:
        cfg["jarvis_usuario"] = usuario
        cfg["jarvis_senha"]   = senha
        spinner_inline("Salvando credenciais...", salvar_config, cfg)
        print_resultado(True, f"Login OK! Credenciais salvas para {usuario}.")
    else:
        print_resultado(False, f"Login falhou: {erro}")
        linha_texto("  Credenciais NAO foram salvas.", C_AVISO)
        linha_vazia()
        forcar = input_campo("Salvar mesmo assim? (s/n)", "n")
        if forcar.strip().lower() == "s":
            cfg["jarvis_usuario"] = usuario
            cfg["jarvis_senha"]   = senha
            spinner_inline("Salvando credenciais...", salvar_config, cfg)
            print_resultado(True, "Credenciais salvas (sem verificacao).")

    aguardar_enter()
    return cfg

# ══════════════════════════════════════════════════════════════════════════════
# DELEGATES
# ══════════════════════════════════════════════════════════════════════════════

def tela_instalar_suricata(cfg: dict):
    from suricata.instalador import executar_instalacao
    return executar_instalacao(cfg)

def tela_diagnostico(cfg: dict):
    from suricata.diagnostico import executar_diagnostico
    return executar_diagnostico(cfg)
