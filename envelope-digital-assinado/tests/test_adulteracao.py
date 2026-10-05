"""Envelopes adulterados, chaves erradas e JSON malformado: sempre um erro controlado."""

import copy

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from envelope_digital import Parametros, abrir_envelope, criar_envelope, verificar_assinatura
from envelope_digital import cripto
from envelope_digital.codificacao import codificar, decodificar
from envelope_digital.erros import (
    AssinaturaInvalidaErro,
    CodificacaoErro,
    DecifragemErro,
    EnvelopeErro,
    FormatoEnvelopeErro,
)

from .conftest import TEXTO_EXEMPLO


@pytest.fixture
def env(remetente, destinatario):
    return criar_envelope(TEXTO_EXEMPLO, destinatario.publica, remetente.privada, Parametros(codificacao="Hex"))


def _trocar_char(valor: str, pos: int = 10) -> str:
    novo = "0" if valor[pos] != "0" else "1"
    return valor[:pos] + novo + valor[pos + 1:]


@pytest.mark.parametrize("campo", ["mensagem_cifrada", "assinatura"])
def test_alterar_criptograma_ou_assinatura_viola_integridade(env, remetente, destinatario, campo):
    env["envelope"][campo] = _trocar_char(env["envelope"][campo])
    with pytest.raises(AssinaturaInvalidaErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_verificacao_vem_antes_da_decifragem(env, remetente, destinatario, monkeypatch):
    """Com a assinatura inválida, nenhuma operação de decifragem deve ser chamada."""
    chamadas = []
    monkeypatch.setattr(cripto, "rsa_oaep_decifrar", lambda *a: chamadas.append("rsa"))
    monkeypatch.setattr(cripto, "aes_decifrar", lambda *a: chamadas.append("aes"))
    env["envelope"]["mensagem_cifrada"] = _trocar_char(env["envelope"]["mensagem_cifrada"])
    with pytest.raises(AssinaturaInvalidaErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)
    assert chamadas == []


def test_alterar_chave_de_sessao(env, remetente, destinatario):
    env["envelope"]["chave_sessao"] = _trocar_char(env["envelope"]["chave_sessao"])
    with pytest.raises(DecifragemErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_iv_nao_e_coberto_pela_assinatura(env, remetente, destinatario):
    """Limitação do protocolo: o IV não é assinado. Alterá-lo muda o 1º bloco do
    texto sem que a assinatura acuse. Documentado no README."""
    env["envelope"]["iv"] = _trocar_char(env["envelope"]["iv"], 0)
    resultado = abrir_envelope(env, destinatario.privada, remetente.publica)
    original = TEXTO_EXEMPLO.encode()
    assert resultado.texto != original
    assert resultado.texto[16:] == original[16:]  # só o primeiro bloco é afetado


def test_chave_privada_do_destinatario_errada(env, remetente, intruso):
    with pytest.raises(DecifragemErro):
        abrir_envelope(env, intruso.privada, remetente.publica)


def test_chave_publica_do_remetente_errada(env, destinatario, intruso):
    with pytest.raises(AssinaturaInvalidaErro):
        abrir_envelope(env, destinatario.privada, intruso.publica)
    with pytest.raises(AssinaturaInvalidaErro):
        verificar_assinatura(env, intruso.publica)


def test_hash_da_assinatura_divergente(env, remetente, destinatario):
    env["parametros"]["hash_assinatura"] = "SHA-512"
    with pytest.raises(AssinaturaInvalidaErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_hash_oaep_divergente(env, remetente, destinatario):
    env["parametros"]["hash_oaep"] = "SHA-512"
    with pytest.raises(DecifragemErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_codificacao_divergente(env, remetente, destinatario):
    env["parametros"]["codificacao"] = "Base64"  # campos estão em Hex
    with pytest.raises(EnvelopeErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_iv_com_tamanho_errado(env, remetente, destinatario):
    env["envelope"]["iv"] = env["envelope"]["iv"][:-2]
    with pytest.raises(FormatoEnvelopeErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_campo_com_codificacao_invalida(env, remetente, destinatario):
    env["envelope"]["chave_sessao"] = "nao-e-hex!"
    with pytest.raises(CodificacaoErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


@pytest.mark.parametrize("secao,campo", [
    ("envelope", "iv"), ("envelope", "chave_sessao"), ("envelope", "mensagem_cifrada"),
    ("envelope", "assinatura"), ("parametros", "hash_oaep"), ("parametros", "hash_assinatura"),
    ("parametros", "codificacao"),
])
def test_campo_obrigatorio_ausente(env, remetente, destinatario, secao, campo):
    del env[secao][campo]
    with pytest.raises(FormatoEnvelopeErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


@pytest.mark.parametrize("campo,valor", [
    ("algoritmo_simetrico", "AES-128-CBC"), ("padding_simetrico", "ZeroPadding"),
    ("algoritmo_chave", "RSA-PKCS1"), ("algoritmo_assinatura", "ECDSA"),
    ("hash_oaep", "MD5"), ("hash_assinatura", "SHA-1"), ("codificacao", "Base32"),
])
def test_parametro_nao_suportado(env, remetente, destinatario, campo, valor):
    env["parametros"][campo] = valor
    with pytest.raises(FormatoEnvelopeErro):
        abrir_envelope(env, destinatario.privada, remetente.publica)


def test_parametro_fixo_ausente_gera_aviso(env, remetente, destinatario):
    del env["parametros"]["padding_simetrico"]
    resultado = abrir_envelope(env, destinatario.privada, remetente.publica)
    assert resultado.texto.decode() == TEXTO_EXEMPLO
    assert any("padding_simetrico" in a for a in resultado.avisos)


@pytest.mark.parametrize("dados", [None, [], "texto", {"parametros": {}}, {"envelope": {}}, {"parametros": 1, "envelope": 2}])
def test_estrutura_invalida(dados, remetente, destinatario):
    with pytest.raises(FormatoEnvelopeErro):
        abrir_envelope(copy.deepcopy(dados), destinatario.privada, remetente.publica)


# ---------------------------------------------------------- compatibilidade
def test_compat_chave_de_sessao_em_bytes_brutos(remetente, destinatario):
    """Outro grupo pode cifrar os 32 bytes brutos da chave: abre com aviso."""
    chave, iv = cripto.gerar_chave_sessao(), cripto.gerar_iv()
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    msg = codificar(cripto.aes_cifrar(chave, iv, b"compat"), "Base64")
    env = {
        "parametros": Parametros().para_json(),
        "envelope": {
            "iv": codificar(iv, "Base64"),
            "chave_sessao": codificar(destinatario.publica.encrypt(chave, oaep), "Base64"),
            "mensagem_cifrada": msg,
            "assinatura": codificar(cripto.assinar(remetente.privada, msg.encode(), "SHA-256"), "Base64"),
        },
    }
    r = abrir_envelope(env, destinatario.privada, remetente.publica)
    assert r.texto == b"compat"
    assert any("BRUTOS" in a for a in r.avisos)


def test_compat_assinatura_sobre_bytes_brutos(remetente, destinatario):
    env = criar_envelope("compat", destinatario.publica, remetente.privada)
    bruto = decodificar(env["envelope"]["mensagem_cifrada"], "Base64")
    env["envelope"]["assinatura"] = codificar(cripto.assinar(remetente.privada, bruto, "SHA-256"), "Base64")
    r = abrir_envelope(env, destinatario.privada, remetente.publica)
    assert r.texto == b"compat"
    assert any("assinatura" in a for a in r.avisos)
