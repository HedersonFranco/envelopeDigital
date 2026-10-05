"""Interface de linha de comando.

Sem argumentos, abre o menu interativo. Com argumentos, executa um subcomando:

    envelope gerar-chaves --nome remetente
    envelope cifrar   -e mensagem.txt --pub-destinatario d_pub.pem --priv-remetente r_priv.pem -o envelope.json
    envelope decifrar -e envelope.json --priv-destinatario d_priv.pem --pub-remetente r_pub.pem -o saida.txt
    envelope verificar -e envelope.json --pub-remetente r_pub.pem

Códigos de saída: 0 sucesso; 1 erro; 2 uso incorreto; 3 assinatura inválida; 130 interrompido.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Sequence

from . import __version__, operacoes, saida
from .codificacao import CODIFICACOES, normalizar_codificacao
from .cripto import HASHES, normalizar_hash
from .envelope import Parametros
from .erros import EnvelopeErro

PROG = "envelope"

# Tradução das mensagens internas do argparse (o módulo usa gettext via ``_``).
_TRADUCOES = {
    "usage: ": "uso: ",
    "options": "opções",
    "optional arguments": "opções",
    "positional arguments": "argumentos posicionais",
    "show this help message and exit": "mostra esta ajuda e sai",
    "show program's version number and exit": "mostra a versão do programa e sai",
    "the following arguments are required: %s": "argumentos obrigatórios ausentes: %s",
    "one of the arguments %s is required": "informe um dos argumentos: %s",
    "argument %(argument_name)s: %(message)s": "argumento %(argument_name)s: %(message)s",
    "not allowed with argument %s": "não pode ser usado junto com %s",
    "expected one argument": "esperava um valor",
    "unrecognized arguments: %s": "argumentos não reconhecidos: %s",
    "invalid choice: %(value)r (choose from %(choices)s)": "opção inválida: %(value)r (escolha entre %(choices)s)",
    "ambiguous option: %(option)s could match %(matches)s": "opção ambígua: %(option)s pode ser %(matches)s",
}
_gettext_original = getattr(argparse, "_", None)

if callable(_gettext_original):

    def _traduzir(texto: str) -> str:
        return _TRADUCOES.get(texto, _gettext_original(texto))

    argparse._ = _traduzir  # type: ignore[attr-defined]


# ------------------------------------------------------------------ tipos argparse
def _tipo_hash(valor: str) -> str:
    try:
        return normalizar_hash(valor)
    except EnvelopeErro:
        raise argparse.ArgumentTypeError(f"use {' ou '.join(HASHES)} (recebido: {valor!r})") from None


def _tipo_codificacao(valor: str) -> str:
    try:
        return normalizar_codificacao(valor)
    except EnvelopeErro:
        raise argparse.ArgumentTypeError(f"use {' ou '.join(CODIFICACOES)} (recebido: {valor!r})") from None


def _tipo_bits(valor: str) -> int:
    try:
        bits = int(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"número inteiro esperado (recebido: {valor!r})") from None
    if bits < 2048:
        raise argparse.ArgumentTypeError("use pelo menos 2048 bits")
    return bits


class _Parser(argparse.ArgumentParser):
    """ArgumentParser com mensagem de erro em português."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"[ERRO] Uso incorreto: {message}", file=sys.stderr)
        print(f"       Dica: execute '{self.prog} --help' para ver as opções.", file=sys.stderr)
        raise SystemExit(2)


def construir_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Envelope digital assinado: AES-256-CBC + RSA-OAEP + assinatura RSA (Encrypt-then-Sign). "
        "Execute sem argumentos para abrir o menu interativo.",
    )
    parser.add_argument("--versao", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="comando", metavar="COMANDO", parser_class=_Parser)

    # gerar-chaves
    g = sub.add_parser("gerar-chaves", help="gera um par de chaves RSA em PEM")
    g.add_argument("--nome", required=True, metavar="NOME", help="prefixo dos arquivos (ex.: remetente, destinatario)")
    g.add_argument("--pasta", default="chaves", metavar="PASTA", help="pasta de destino (padrão: chaves)")
    g.add_argument("--bits", type=_tipo_bits, default=2048, metavar="BITS", help="tamanho da chave (padrão: 2048)")
    g.add_argument("--com-senha", action="store_true", help="protege a chave privada com senha")
    g.add_argument("--sobrescrever", action="store_true", help="substitui chaves existentes com o mesmo nome")

    # cifrar
    c = sub.add_parser("cifrar", help="cria o envelope (cifra e assina)")
    origem = c.add_mutually_exclusive_group(required=True)
    origem.add_argument("-e", "--entrada", metavar="ARQUIVO", help="arquivo de texto UTF-8 a cifrar")
    origem.add_argument("-t", "--texto", metavar="TEXTO", help="texto a cifrar, digitado na linha de comando")
    c.add_argument("--pub-destinatario", required=True, metavar="PEM", help="chave pública do destinatário (PEM)")
    c.add_argument("--priv-remetente", required=True, metavar="PEM", help="chave privada do remetente (PEM)")
    c.add_argument("-o", "--saida", default="envelope.json", metavar="JSON", help="arquivo JSON de saída (padrão: envelope.json)")
    c.add_argument("--hash-oaep", type=_tipo_hash, metavar="HASH", default="SHA-256", help="SHA-256 (padrão) ou SHA-512")
    c.add_argument("--hash-assinatura", type=_tipo_hash, metavar="HASH", default="SHA-256", help="SHA-256 (padrão) ou SHA-512")
    c.add_argument("--codificacao", type=_tipo_codificacao, metavar="COD", default="Base64", help="Base64 (padrão) ou Hex")
    c.add_argument("--pedir-senha", action="store_true", help="pergunta a senha da chave privada")

    # decifrar
    d = sub.add_parser("decifrar", help="abre o envelope (verifica a assinatura e decifra)")
    d.add_argument("-e", "--envelope", required=True, metavar="JSON", help="arquivo JSON do envelope")
    d.add_argument("--priv-destinatario", required=True, metavar="PEM", help="chave privada do destinatário (PEM)")
    d.add_argument("--pub-remetente", required=True, metavar="PEM", help="chave pública do remetente (PEM)")
    d.add_argument("-o", "--saida", default="mensagem_decifrada.txt", metavar="ARQUIVO",
                   help="arquivo de saída (padrão: mensagem_decifrada.txt)")
    d.add_argument("--mostrar", action="store_true", help="também exibe o texto decifrado no terminal")
    d.add_argument("--pedir-senha", action="store_true", help="pergunta a senha da chave privada")

    # verificar
    v = sub.add_parser("verificar", help="apenas verifica a assinatura do envelope")
    v.add_argument("-e", "--envelope", required=True, metavar="JSON", help="arquivo JSON do envelope")
    v.add_argument("--pub-remetente", required=True, metavar="PEM", help="chave pública do remetente (PEM)")

    sub.add_parser("menu", help="abre o menu interativo")
    return parser


def _senha(pedir: bool, rotulo: str = "Senha da chave privada: ") -> str | None:
    if not pedir:
        return None
    return getpass.getpass(rotulo) or None


# ------------------------------------------------------------------ execução
def _executar(args: argparse.Namespace) -> int:
    if args.comando == "gerar-chaves":
        senha = None
        if args.com_senha:
            senha = getpass.getpass("Nova senha da chave privada: ")
            if not senha:
                saida.erro("A senha não pode ser vazia.")
                return 1
            if getpass.getpass("Confirme a senha: ") != senha:
                saida.erro("As senhas não conferem.")
                return 1
        priv, pub = operacoes.gerar_chaves(args.pasta, args.nome, args.bits, senha, args.sobrescrever)
        saida.ok(f"Par de chaves RSA-{args.bits} gerado.")
        saida.info(f"Privada: {priv}  (guarde em segredo)")
        saida.info(f"Pública: {pub}")
        return 0

    if args.comando == "cifrar":
        p = Parametros(args.hash_oaep, args.hash_assinatura, args.codificacao)
        resumo = operacoes.cifrar(
            entrada=args.entrada,
            texto=args.texto,
            pub_destinatario=args.pub_destinatario,
            priv_remetente=args.priv_remetente,
            saida=args.saida,
            parametros=p,
            senha=_senha(args.pedir_senha),
        )
        saida.ok(f"Envelope criado: {resumo.saida}")
        saida.info(f"Texto cifrado: {resumo.tamanho_texto} bytes")
        saida.info(f"OAEP: {p.hash_oaep} | Assinatura: RSA/{p.hash_assinatura} | Codificação: {p.codificacao}")
        return 0

    if args.comando == "decifrar":
        resultado = operacoes.decifrar(
            envelope=args.envelope,
            priv_destinatario=args.priv_destinatario,
            pub_remetente=args.pub_remetente,
            saida=args.saida,
            senha=_senha(args.pedir_senha),
        )
        for a in resultado.avisos:
            saida.aviso(a)
        saida.ok("Assinatura válida: o criptograma é íntegro e foi assinado pelo remetente.")
        saida.ok(f"Mensagem decifrada gravada em: {args.saida} ({len(resultado.texto)} bytes)")
        texto = resultado.texto_utf8()
        if texto is None:
            saida.aviso("O conteúdo decifrado não é texto UTF-8 válido; foi gravado como bytes.")
        elif args.mostrar:
            print("----- início da mensagem -----")
            print(texto)
            print("------ fim da mensagem -------")
        return 0

    if args.comando == "verificar":
        avisos = operacoes.verificar(envelope=args.envelope, pub_remetente=args.pub_remetente)
        for a in avisos:
            saida.aviso(a)
        saida.ok("Assinatura válida: o criptograma é íntegro e foi assinado pelo remetente.")
        return 0

    raise AssertionError(f"comando desconhecido: {args.comando}")


def main(argv: Sequence[str] | None = None) -> int:
    saida.configurar_console()
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if not argv:
            from .menu import executar_menu

            return executar_menu()
        args = construir_parser().parse_args(argv)
        if args.comando in (None, "menu"):
            from .menu import executar_menu

            return executar_menu()
        return _executar(args)
    except EnvelopeErro as exc:
        saida.erro(exc)
        return exc.codigo_saida
    except KeyboardInterrupt:
        print(file=sys.stderr)
        saida.erro("Operação interrompida pelo usuário.")
        return 130
    except SystemExit as exc:  # argparse (--help, --versao, uso incorreto)
        return exc.code if isinstance(exc.code, int) else 0
    except Exception as exc:  # noqa: BLE001 - rede de segurança: nunca mostrar stack trace
        saida.erro(f"Erro inesperado ({type(exc).__name__}): {exc}")
        saida.info("Se o problema persistir, abra uma issue com o comando executado.")
        return 1
