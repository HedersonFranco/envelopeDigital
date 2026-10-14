import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from envelope_digital import Parametros, criar_envelope
from envelope_digital.chaves import carregar_chave_privada, carregar_chave_publica, gerar_par_de_chaves
from envelope_digital.erros import ArquivoErro, ChaveInvalidaErro, ChaveProtegidaErro


def _gravar(caminho, chave, privada=True, senha=None):
    if privada:
        enc = serialization.BestAvailableEncryption(senha) if senha else serialization.NoEncryption()
        dados = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    else:
        dados = chave.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    caminho.write_bytes(dados)
    return caminho


def test_arquivo_inexistente(tmp_path):
    with pytest.raises(ArquivoErro):
        carregar_chave_publica(tmp_path / "nao_existe.pem")
    with pytest.raises(ArquivoErro):
        carregar_chave_privada(tmp_path)  # pasta, não arquivo


def test_arquivo_que_nao_e_pem(tmp_path):
    (tmp_path / "x.pem").write_text("isto não é uma chave")
    with pytest.raises(ChaveInvalidaErro):
        carregar_chave_publica(tmp_path / "x.pem")


def test_pem_corrompido(tmp_path):
    (tmp_path / "x.pem").write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
    with pytest.raises(ChaveInvalidaErro):
        carregar_chave_publica(tmp_path / "x.pem")


def test_chaves_trocadas(remetente):
    with pytest.raises(ChaveInvalidaErro, match="PRIVADA"):
        carregar_chave_publica(remetente.privada_pem)
    with pytest.raises(ChaveInvalidaErro):
        carregar_chave_privada(remetente.publica_pem)


def test_chave_nao_rsa(tmp_path):
    chave = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ChaveInvalidaErro, match="RSA"):
        carregar_chave_privada(_gravar(tmp_path / "ec.pem", chave))
    with pytest.raises(ChaveInvalidaErro, match="RSA"):
        carregar_chave_publica(_gravar(tmp_path / "ec_pub.pem", chave.public_key(), privada=False))


def test_chave_com_senha(tmp_path):
    priv, _ = gerar_par_de_chaves(tmp_path, "protegida", senha="s3nh@")
    with pytest.raises(ChaveProtegidaErro):
        carregar_chave_privada(priv)
    with pytest.raises(ChaveInvalidaErro):
        carregar_chave_privada(priv, senha="errada")
    assert isinstance(carregar_chave_privada(priv, senha="s3nh@"), rsa.RSAPrivateKey)


def test_senha_informada_para_chave_sem_senha(remetente):
    with pytest.raises(ChaveInvalidaErro):
        carregar_chave_privada(remetente.privada_pem, senha="qualquer")


def test_formato_pkcs1_tradicional(tmp_path):
    """Chaves no formato 'BEGIN RSA PRIVATE KEY' (openssl genrsa antigo) também funcionam."""
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = chave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption())
    (tmp_path / "trad.pem").write_bytes(pem)
    pub = chave.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    (tmp_path / "trad_pub.pem").write_bytes(pub)
    assert carregar_chave_privada(tmp_path / "trad.pem")
    assert carregar_chave_publica(tmp_path / "trad_pub.pem")


def test_gerar_nao_sobrescreve(tmp_path):
    gerar_par_de_chaves(tmp_path, "par")
    with pytest.raises(ArquivoErro):
        gerar_par_de_chaves(tmp_path, "par")
    gerar_par_de_chaves(tmp_path, "par", sobrescrever=True)


@pytest.mark.parametrize("nome", ["", "a/b", "c:d"])
def test_gerar_nome_invalido(tmp_path, nome):
    with pytest.raises(ArquivoErro):
        gerar_par_de_chaves(tmp_path, nome)


def test_gerar_chave_pequena(tmp_path):
    with pytest.raises(ChaveInvalidaErro):
        gerar_par_de_chaves(tmp_path, "pequena", bits=1024)


def test_chave_pequena_demais_para_oaep_sha512(remetente):
    """RSA-1024 com OAEP/SHA-512 só cifra 0 bytes: erro claro, não exceção crua."""
    pequena = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ChaveInvalidaErro, match="2048"):
        criar_envelope("x", pequena.public_key(), remetente.privada, Parametros(hash_oaep="SHA-512"))
