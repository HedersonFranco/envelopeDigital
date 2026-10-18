"""Conformidade com o protocolo e ida-e-volta nas 8 combinações de parâmetros."""

import itertools
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from envelope_digital import Parametros, abrir_envelope, criar_envelope
from envelope_digital.codificacao import decodificar

from .conftest import TEXTO_EXEMPLO

HASHES = ["SHA-256", "SHA-512"]
CODS = ["Base64", "Hex"]
COMBINACOES = list(itertools.product(HASHES, HASHES, CODS))
_HASH = {"SHA-256": hashes.SHA256, "SHA-512": hashes.SHA512}


@pytest.mark.parametrize("hash_oaep,hash_sig,cod", COMBINACOES)
def test_ida_e_volta_todas_as_combinacoes(remetente, destinatario, hash_oaep, hash_sig, cod):
    p = Parametros(hash_oaep, hash_sig, cod)
    env = criar_envelope(TEXTO_EXEMPLO, destinatario.publica, remetente.privada, p)
    env = json.loads(json.dumps(env))  # simula gravar e ler o arquivo
    resultado = abrir_envelope(env, destinatario.privada, remetente.publica)
    assert resultado.texto.decode("utf-8") == TEXTO_EXEMPLO
    assert resultado.avisos == []


def test_estrutura_json_exata(remetente, destinatario):
    env = criar_envelope("x", destinatario.publica, remetente.privada, Parametros("SHA-512", "SHA-256", "Hex"))
    assert list(env) == ["parametros", "envelope"]
    assert env["parametros"] == {
        "algoritmo_simetrico": "AES-256-CBC",
        "padding_simetrico": "PKCS7",
        "algoritmo_chave": "RSA-OAEP",
        "hash_oaep": "SHA-512",
        "algoritmo_assinatura": "RSA",
        "hash_assinatura": "SHA-256",
        "codificacao": "Hex",
    }
    assert list(env["envelope"]) == ["iv", "chave_sessao", "mensagem_cifrada", "assinatura"]


@pytest.mark.parametrize("cod", CODS)
def test_tamanhos_e_conteudo_conforme_especificacao(remetente, destinatario, cod):
    """Confere, de forma independente, cada passo da seção 3.1 do enunciado."""
    p = Parametros("SHA-256", "SHA-256", cod)
    env = criar_envelope(TEXTO_EXEMPLO, destinatario.publica, remetente.privada, p)
    e = env["envelope"]

    assert len(decodificar(e["iv"], cod)) == 16

    # Passo 3: o RSA-OAEP cifra o TEXTO codificado da chave de 32 bytes
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    chave_txt = destinatario.privada.decrypt(decodificar(e["chave_sessao"], cod), oaep).decode("ascii")
    assert len(decodificar(chave_txt, cod)) == 32
    assert len(chave_txt) == (44 if cod == "Base64" else 64)

    # Passo 5: a assinatura PKCS#1 v1.5 é sobre o TEXTO codificado do criptograma
    remetente.publica.verify(
        decodificar(e["assinatura"], cod),
        e["mensagem_cifrada"].encode("ascii"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def test_segredos_aleatorios_a_cada_envelope(remetente, destinatario):
    a = criar_envelope("mesma mensagem", destinatario.publica, remetente.privada)
    b = criar_envelope("mesma mensagem", destinatario.publica, remetente.privada)
    for campo in ("iv", "chave_sessao", "mensagem_cifrada", "assinatura"):
        assert a["envelope"][campo] != b["envelope"][campo]


@pytest.mark.parametrize("texto", [b"", b"a", b"x" * 16, b"y" * 1_000_000])
def test_tamanhos_de_mensagem(remetente, destinatario, texto):
    env = criar_envelope(texto, destinatario.publica, remetente.privada)
    assert abrir_envelope(env, destinatario.privada, remetente.publica).texto == texto


def test_padroes(remetente, destinatario):
    env = criar_envelope("x", destinatario.publica, remetente.privada)
    p = env["parametros"]
    assert (p["hash_oaep"], p["hash_assinatura"], p["codificacao"]) == ("SHA-256", "SHA-256", "Base64")


def test_leitura_tolerante_de_parametros(remetente, destinatario):
    env = criar_envelope("tolerante", destinatario.publica, remetente.privada, Parametros("SHA-512", "SHA-512", "Hex"))
    env["parametros"].update(hash_oaep="sha512", hash_assinatura="SHA_512", codificacao="HEX",
                             padding_simetrico="PKCS#5", algoritmo_simetrico="aes-256-cbc")
    env["envelope"]["mensagem_cifrada"] = env["envelope"]["mensagem_cifrada"].upper()
    # A assinatura é sobre o texto exato do campo; ao trocar o caso, ela deixa de conferir.
    from envelope_digital.erros import AssinaturaInvalidaErro

    with pytest.raises(AssinaturaInvalidaErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)
    env["envelope"]["mensagem_cifrada"] = env["envelope"]["mensagem_cifrada"].lower()
    assert abrir_envelope(env, destinatario.privada, remetente.publica).texto == "tolerante".encode()
