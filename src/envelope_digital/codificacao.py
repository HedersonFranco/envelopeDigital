"""Codificação textual dos artefatos binários (Base64 ou Hex).

Política de interoperabilidade:
- na escrita, o formato é sempre canônico: Base64 padrão (RFC 4648, alfabeto
  ``+/`` com ``=``) em uma única linha, ou Hex em minúsculas;
- na leitura, o programa é tolerante: ignora espaços e quebras de linha e
  aceita Hex em maiúsculas ou minúsculas.
"""

from __future__ import annotations

import base64
import binascii
import re

from .erros import CodificacaoErro, FormatoEnvelopeErro

BASE64 = "Base64"
HEX = "Hex"
CODIFICACOES = (BASE64, HEX)

_ESPACOS = re.compile(r"\s+")


def normalizar_codificacao(nome: str) -> str:
    """Converte variações como ``base64``, ``HEX`` ou ``hexadecimal`` no nome canônico."""
    if not isinstance(nome, str):
        raise FormatoEnvelopeErro(
            "O parâmetro 'codificacao' deve ser um texto.",
            "Use \"Base64\" ou \"Hex\".",
        )
    chave = nome.strip().lower().replace("-", "").replace("_", "")
    if chave in ("base64", "b64"):
        return BASE64
    if chave in ("hex", "hexadecimal", "base16"):
        return HEX
    raise FormatoEnvelopeErro(
        f"Codificação não suportada: {nome!r}.",
        "Use \"Base64\" ou \"Hex\".",
    )


def codificar(dados: bytes, codificacao: str) -> str:
    """Converte bytes em texto na codificação escolhida."""
    cod = normalizar_codificacao(codificacao)
    if cod == BASE64:
        return base64.b64encode(dados).decode("ascii")
    return dados.hex()


def decodificar(texto: str, codificacao: str, campo: str = "valor") -> bytes:
    """Converte texto Base64/Hex em bytes, com mensagem de erro que cita o campo."""
    cod = normalizar_codificacao(codificacao)
    if not isinstance(texto, str):
        raise CodificacaoErro(f"O campo '{campo}' deve ser um texto {cod}.")
    limpo = _ESPACOS.sub("", texto)
    if not limpo:
        raise CodificacaoErro(f"O campo '{campo}' está vazio.")
    try:
        if cod == BASE64:
            return base64.b64decode(limpo, validate=True)
        return bytes.fromhex(limpo)
    except (binascii.Error, ValueError):
        outra = HEX if cod == BASE64 else BASE64
        raise CodificacaoErro(
            f"O campo '{campo}' não é {cod} válido.",
            f"Confira se o envelope não foi corrompido e se o parâmetro "
            f"'codificacao' está correto (talvez o campo esteja em {outra}).",
        ) from None
