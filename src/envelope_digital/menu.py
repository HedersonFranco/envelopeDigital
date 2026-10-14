"""Menu interativo (aberto quando o programa é executado sem argumentos)."""

from __future__ import annotations

import getpass
from pathlib import Path
from typing import Callable, TypeVar

from . import __version__, operacoes, saida
from .chaves import carregar_chave_privada
from .codificacao import CODIFICACOES
from .cripto import HASHES
from .envelope import Parametros
from .erros import ChaveProtegidaErro, EnvelopeErro

T = TypeVar("T")

CABECALHO = f"""
==============================================================
   ENVELOPE DIGITAL ASSINADO  v{__version__}
   AES-256-CBC  +  RSA-OAEP  +  Assinatura RSA (Encrypt-then-Sign)
=============================================================="""

OPCOES = """
  1) Gerar par de chaves RSA
  2) Criar envelope   (cifrar e assinar)
  3) Abrir envelope   (verificar assinatura e decifrar)
  4) Apenas verificar a assinatura de um envelope
  5) Ajuda
  0) Sair
"""

AJUDA = """
Como funciona:
  * O REMETENTE cifra com a chave PÚBLICA do destinatário e assina com
    a sua própria chave PRIVADA.
  * O DESTINATÁRIO verifica a assinatura com a chave PÚBLICA do remetente
    e decifra com a sua própria chave PRIVADA.

Fluxo típico de teste:
  1) Gere dois pares: um com nome 'remetente' e outro com 'destinatario'.
  2) Crie o envelope usando destinatario_publica.pem e remetente_privada.pem.
  3) Abra o envelope usando destinatario_privada.pem e remetente_publica.pem.

Dica: pressione Enter para aceitar o valor padrão mostrado entre [colchetes].
Ctrl+C cancela a operação atual e volta ao menu.
"""


class _Sair(Exception):
    """Fim da entrada padrão (Ctrl+D / Ctrl+Z): encerra o menu."""


def _ler(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError:
        raise _Sair from None


def perguntar(rotulo: str, padrao: str | None = None, obrigatorio: bool = True) -> str:
    sufixo = f" [{padrao}]" if padrao else ""
    while True:
        valor = _ler(f"  {rotulo}{sufixo}: ").strip().strip('"').strip("'")
        if not valor and padrao is not None:
            return padrao
        if valor or not obrigatorio:
            return valor
        print("  Valor obrigatório.")


def escolher(rotulo: str, opcoes: tuple[str, ...], padrao: str) -> str:
    texto_opcoes = " / ".join(f"{i}={o}" for i, o in enumerate(opcoes, 1))
    while True:
        valor = perguntar(f"{rotulo} ({texto_opcoes})", padrao)
        if valor in opcoes:
            return valor
        if valor.isdigit() and 1 <= int(valor) <= len(opcoes):
            return opcoes[int(valor) - 1]
        for o in opcoes:
            if valor.lower().replace("-", "") == o.lower().replace("-", ""):
                return o
        print("  Opção inválida.")


def confirmar(rotulo: str, padrao: bool = False) -> bool:
    valor = perguntar(f"{rotulo} (s/n)", "s" if padrao else "n").lower()
    return valor in ("s", "sim", "y", "yes")


def arquivo_saida(rotulo: str, padrao: str) -> str | None:
    caminho = perguntar(rotulo, padrao)
    if Path(caminho).exists() and not confirmar(f"'{caminho}' já existe. Sobrescrever?"):
        print("  Operação cancelada.")
        return None
    return caminho


def senha_se_necessario(caminho: str) -> str | None:
    """Testa a chave privada; se estiver protegida, pede a senha."""
    try:
        carregar_chave_privada(caminho)
        return None
    except ChaveProtegidaErro:
        try:
            return getpass.getpass("  A chave privada está protegida. Senha: ") or None
        except EOFError:
            raise _Sair from None
    except EnvelopeErro:
        return None  # o erro real será mostrado pela operação


# ------------------------------------------------------------------ ações
def acao_gerar() -> None:
    nome = perguntar("Nome do par (ex.: remetente, destinatario)")
    pasta = perguntar("Pasta de destino", "chaves")
    bits = int(escolher("Tamanho da chave em bits", ("2048", "3072", "4096"), "2048"))
    senha = None
    if confirmar("Proteger a chave privada com senha?"):
        senha = getpass.getpass("  Nova senha: ")
        if not senha or getpass.getpass("  Confirme a senha: ") != senha:
            saida.erro("Senha vazia ou as senhas não conferem.")
            return
    sobrescrever = False
    if (Path(pasta) / f"{nome}_privada.pem").exists() or (Path(pasta) / f"{nome}_publica.pem").exists():
        sobrescrever = confirmar("Já existe um par com esse nome. Sobrescrever?")
        if not sobrescrever:
            print("  Operação cancelada.")
            return
    priv, pub = operacoes.gerar_chaves(pasta, nome, bits, senha, sobrescrever)
    saida.ok(f"Par de chaves RSA-{bits} gerado.")
    saida.info(f"Privada: {priv}  (guarde em segredo)")
    saida.info(f"Pública: {pub}")


def acao_cifrar() -> None:
    origem = escolher("Origem da mensagem", ("arquivo", "digitar"), "arquivo")
    entrada = texto = None
    if origem == "arquivo":
        entrada = perguntar("Arquivo de texto (UTF-8)", "mensagem.txt")
    else:
        texto = perguntar("Digite a mensagem")
    pub_dest = perguntar("Chave PÚBLICA do destinatário", "chaves/destinatario_publica.pem")
    priv_rem = perguntar("Chave PRIVADA do remetente", "chaves/remetente_privada.pem")
    hash_oaep = escolher("Hash do RSA-OAEP", tuple(HASHES), "SHA-256")
    hash_sig = escolher("Hash da assinatura", tuple(HASHES), "SHA-256")
    cod = escolher("Codificação", CODIFICACOES, "Base64")
    destino = arquivo_saida("Arquivo de saída do envelope", "envelope.json")
    if destino is None:
        return
    p = Parametros(hash_oaep, hash_sig, cod)
    resumo = operacoes.cifrar(
        entrada=entrada, texto=texto, pub_destinatario=pub_dest, priv_remetente=priv_rem,
        saida=destino, parametros=p, senha=senha_se_necessario(priv_rem),
    )
    saida.ok(f"Envelope criado: {resumo.saida} ({resumo.tamanho_texto} bytes de texto cifrados)")


def acao_decifrar() -> None:
    env = perguntar("Arquivo do envelope", "envelope.json")
    priv_dest = perguntar("Chave PRIVADA do destinatário", "chaves/destinatario_privada.pem")
    pub_rem = perguntar("Chave PÚBLICA do remetente", "chaves/remetente_publica.pem")
    destino = arquivo_saida("Arquivo de saída do texto decifrado", "mensagem_decifrada.txt")
    if destino is None:
        return
    resultado = operacoes.decifrar(
        envelope=env, priv_destinatario=priv_dest, pub_remetente=pub_rem,
        saida=destino, senha=senha_se_necessario(priv_dest),
    )
    for a in resultado.avisos:
        saida.aviso(a)
    saida.ok("Assinatura válida.")
    saida.ok(f"Mensagem decifrada gravada em: {destino}")
    texto = resultado.texto_utf8()
    if texto is None:
        saida.aviso("O conteúdo decifrado não é texto UTF-8 válido.")
    elif confirmar("Exibir a mensagem aqui?", padrao=True):
        print("\n----- início da mensagem -----")
        print(texto)
        print("------ fim da mensagem -------")


def acao_verificar() -> None:
    env = perguntar("Arquivo do envelope", "envelope.json")
    pub_rem = perguntar("Chave PÚBLICA do remetente", "chaves/remetente_publica.pem")
    for a in operacoes.verificar(envelope=env, pub_remetente=pub_rem):
        saida.aviso(a)
    saida.ok("Assinatura válida: o criptograma é íntegro e foi assinado pelo remetente.")


ACOES: dict[str, tuple[str, Callable[[], None]]] = {
    "1": ("Gerar par de chaves", acao_gerar),
    "2": ("Criar envelope", acao_cifrar),
    "3": ("Abrir envelope", acao_decifrar),
    "4": ("Verificar assinatura", acao_verificar),
    "5": ("Ajuda", lambda: print(AJUDA)),
}


def executar_menu() -> int:
    print(CABECALHO)
    while True:
        print(OPCOES)
        try:
            opcao = _ler("Escolha uma opção: ").strip()
        except _Sair:
            print()
            return 0
        if opcao in ("0", "q", "sair"):
            print("Até mais!")
            return 0
        if opcao not in ACOES:
            print("Opção inválida.")
            continue
        titulo, funcao = ACOES[opcao]
        print(f"\n--- {titulo} ---")
        try:
            funcao()
        except EnvelopeErro as exc:
            saida.erro(exc)
        except KeyboardInterrupt:
            print()
            saida.aviso("Operação cancelada.")
        except _Sair:
            print()
            return 0
        except Exception as exc:  # noqa: BLE001 - o menu nunca deve fechar por erro
            saida.erro(f"Erro inesperado ({type(exc).__name__}): {exc}")
        try:
            _ler("\nPressione Enter para continuar...")
        except _Sair:
            return 0
