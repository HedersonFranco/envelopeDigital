import os

import pytest

from envelope_digital.codificacao import codificar, decodificar, normalizar_codificacao
from envelope_digital.erros import CodificacaoErro, FormatoEnvelopeErro


@pytest.mark.parametrize("cod", ["Base64", "Hex"])
def test_ida_e_volta(cod):
    dados = os.urandom(100)
    assert decodificar(codificar(dados, cod), cod) == dados


def test_formato_canonico():
    assert codificar(b"\xff\x00\xab", "Hex") == "ff00ab"
    assert codificar(b"\xff\x00\xab", "Base64") == "/wCr"
    longo = codificar(os.urandom(500), "Base64")
    assert "\n" not in longo


def test_leitura_tolerante():
    assert decodificar("FF 00\nAB", "Hex") == b"\xff\x00\xab"
    assert decodificar("/wCr\n", "Base64") == b"\xff\x00\xab"


@pytest.mark.parametrize("entrada,esperado", [
    ("Base64", "Base64"), ("base64", "Base64"), ("BASE64", "Base64"),
    ("Hex", "Hex"), ("hex", "Hex"), ("HEX", "Hex"), ("hexadecimal", "Hex"),
])
def test_normalizar(entrada, esperado):
    assert normalizar_codificacao(entrada) == esperado


def test_codificacao_desconhecida():
    with pytest.raises(FormatoEnvelopeErro):
        normalizar_codificacao("Base32")


@pytest.mark.parametrize("texto,cod", [("zz", "Hex"), ("abc", "Hex"), ("@@@", "Base64"), ("abc", "Base64"), ("", "Hex")])
def test_valor_invalido(texto, cod):
    with pytest.raises(CodificacaoErro):
        decodificar(texto, cod, "campo_teste")
