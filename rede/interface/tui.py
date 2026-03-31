"""
tui.py
Helpers de interface TUI — bordas, cores, inputs padronizados.
Usado por todos os menus do ms_confignet.
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# Cores ANSI
# ─────────────────────────────────────────────────────────────────────────────

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_DIM    = "\033[2m"
C_OK     = "\033[92m"
C_ERRO   = "\033[91m"
C_AVISO  = "\033[93m"
C_TITULO = "\033[96m"
C_WHITE  = "\033[97m"
C_NEON   = "\033[92m\033[2m"
C_BORDA  = "\033[90m"

LARGURA = 62


# ─────────────────────────────────────────────────────────────────────────────
# Primitivos de layout
# ─────────────────────────────────────────────────────────────────────────────

def limpar():
    """Limpa a tela do terminal."""
    os.system("clear")


def topo():
    """Imprime a borda superior da interface."""
    print(C_BORDA + "  +" + "=" * LARGURA + "+" + C_RESET)


def fundo():
    """Imprime a borda inferior da interface."""
    print(C_BORDA + "  +" + "=" * LARGURA + "+" + C_RESET)


def separador():
    """Imprime uma linha separadora dentro do menu."""
    print(C_BORDA + "  +" + "-" * LARGURA + "+" + C_RESET)


def linha_vazia():
    """Imprime uma linha em branco preservando as bordas laterais."""
    print(C_BORDA + "  |" + " " * LARGURA + "|" + C_RESET)


def linha_texto(texto: str, cor: str = C_WHITE, alinhamento: str = "esquerda"):
    """
    Imprime uma linha de texto formatada dentro das bordas.
    Evita quebra de layout truncando textos muito longos.
    """
    texto_puro = str(texto)
    
    # Previne quebra de layout: se for maior que a largura, trunca com "..."
    if len(texto_puro) > LARGURA - 2:
        texto_puro = texto_puro[:LARGURA - 5] + "..."

    if alinhamento == "centro":
        pad = max(0, (LARGURA - len(texto_puro)) // 2)
        conteudo = " " * pad + texto_puro
    else:
        conteudo = " " + texto_puro
        
    conteudo = conteudo.ljust(LARGURA)
    print(C_BORDA + "  |" + cor + conteudo + C_RESET + C_BORDA + "|" + C_RESET)


# ─────────────────────────────────────────────────────────────────────────────
# Cabeçalho padrão
# ─────────────────────────────────────────────────────────────────────────────

def cabecalho(subtitulo: str = ""):
    """Imprime o cabeçalho padrão de todas as telas."""
    limpar()
    topo()
    linha_texto("MOONSHIELD  ·  CONFIG NET  v1.0", C_TITULO, "centro")
    if subtitulo:
        linha_texto(subtitulo, C_DIM, "centro")
    else:
        linha_texto("Configuracao de rede, VLANs e roteamento", C_DIM, "centro")
    separador()


# ─────────────────────────────────────────────────────────────────────────────
# Prints de status
# ─────────────────────────────────────────────────────────────────────────────

def print_ok(msg: str):
    print(C_OK + f"  [OK] {msg}" + C_RESET)


def print_erro(msg: str):
    print(C_ERRO + f"  [!!] {msg}" + C_RESET)


def print_aviso(msg: str):
    print(C_AVISO + f"  [!]  {msg}" + C_RESET)


def print_info(msg: str):
    print(C_DIM + f"  [ ] {msg}" + C_RESET)


# ─────────────────────────────────────────────────────────────────────────────
# Inputs
# ─────────────────────────────────────────────────────────────────────────────

def input_campo(label: str, padrao: str = "") -> str:
    """Solicita um input do usuário com um valor padrão opcional."""
    hint = f" [{padrao}]" if padrao else ""
    print(C_AVISO + f"  > {label}{hint}: " + C_WHITE, end="", flush=True)
    try:
        val = input().strip()
        return val if val else padrao
    except (KeyboardInterrupt, EOFError):
        return padrao


def aguardar_enter():
    """Pausa a execução até o usuário pressionar ENTER."""
    print()
    print(C_DIM + "  Pressione ENTER para continuar..." + C_RESET, end="", flush=True)
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


def ler_opcao(prompt: str = "Opcao") -> str:
    """Lê uma opção do menu, retornando a string em maiúsculo."""
    print(C_AVISO + f"  > {prompt}: " + C_WHITE, end="", flush=True)
    try:
        return input().strip().upper()
    except (KeyboardInterrupt, EOFError):
        return "V"


# ─────────────────────────────────────────────────────────────────────────────
# Exibição de resultados em lote
# ─────────────────────────────────────────────────────────────────────────────

def exibir_resultados(resultados: list[tuple[str, bool, str]]):
    """
    Exibe lista de (etapa, sucesso, mensagem) com formatação padronizada.
    """
    for etapa, ok, msg in resultados:
        if ok:
            print_ok(f"{etapa}: {msg}")
        else:
            print_erro(f"{etapa}: {msg}")


def resumo_resultados(resultados: list[tuple[str, bool, str]]) -> tuple[int, int]:
    """Retorna a contagem de (sucessos, falhas)."""
    ok_count  = sum(1 for _, ok, _ in resultados if ok)
    err_count = sum(1 for _, ok, _ in resultados if not ok)
    return ok_count, err_count