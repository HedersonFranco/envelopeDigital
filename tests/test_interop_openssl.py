"""Interoperabilidade com uma implementação independente: a linha de comando do OpenSSL.

Os testes são ignorados automaticamente se o executável ``openssl`` (3.x) não estiver no PATH.
"""

from __future__ import annotations

import base64
import itertools
import json
import os
import shutil
import subprocess

import pytest

from envelope_digital import Parametros, abrir_envelope, criar_envelope
from envelope_digital.codificacao import codificar, decodificar

from .conftest import TEXTO_EXEMPLO

OPENSSL = shutil.which("openssl")


def _openssl_3() -> bool:
    if not OPENSSL:
        return False
    versao = subprocess.run([OPENSSL, "version"], capture_output=True, text=True).stdout
    return versao.startswith("OpenSSL 3")


pytestmark = pytest.mark.skipif(not _openssl_3(), reason="OpenSSL 3.x não encontrado")

COMBINACOES = list(itertools.product(["SHA-256", "SHA-512"], ["SHA-256", "SHA-512"], ["Base64", "Hex"]))


def _md(nome: str) -> str:
    return nome.replace("-", "").lower()


def _run(*args, entrada: bytes | None = None) -> bytes:
    r = subprocess.run([OPENSSL, *map(str, args)], input=entrada, capture_output=True)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    return r.stdout


@pytest.mark.parametrize("hash_oaep,hash_sig,cod", COMBINACOES)
def test_envelope_do_programa_aberto_pelo_openssl(tmp_path, remetente, destinatario, hash_oaep, hash_sig, cod):
    env = criar_envelope(TEXTO_EXEMPLO, destinatario.publica, remetente.privada, Parametros(hash_oaep, hash_sig, cod))
    e = env["envelope"]

    (tmp_path / "msg").write_bytes(e["mensagem_cifrada"].encode("ascii"))
    (tmp_path / "sig").write_bytes(decodificar(e["assinatura"], cod))
    saida = _run("dgst", f"-{_md(hash_sig)}", "-verify", remetente.publica_pem,
                 "-signature", tmp_path / "sig", tmp_path / "msg")
    assert b"Verified OK" in saida

    (tmp_path / "k").write_bytes(decodificar(e["chave_sessao"], cod))
    chave_txt = _run("pkeyutl", "-decrypt", "-inkey", destinatario.privada_pem, "-in", tmp_path / "k",
                     "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", f"rsa_oaep_md:{_md(hash_oaep)}",
                     "-pkeyopt", f"rsa_mgf1_md:{_md(hash_oaep)}").decode("ascii")
    chave = decodificar(chave_txt, cod)
    assert len(chave) == 32

    texto = _run("enc", "-d", "-aes-256-cbc", "-K", chave.hex(), "-iv", decodificar(e["iv"], cod).hex(),
                 entrada=decodificar(e["mensagem_cifrada"], cod))
    assert texto.decode("utf-8") == TEXTO_EXEMPLO


@pytest.mark.parametrize("hash_oaep,hash_sig,cod", COMBINACOES)
def test_envelope_do_openssl_aberto_pelo_programa(tmp_path, remetente, destinatario, hash_oaep, hash_sig, cod):
    chave, iv = os.urandom(32), os.urandom(16)
    chave_txt = codificar(chave, cod)

    (tmp_path / "k").write_bytes(chave_txt.encode("ascii"))
    chave_cif = _run("pkeyutl", "-encrypt", "-pubin", "-inkey", destinatario.publica_pem, "-in", tmp_path / "k",
                     "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", f"rsa_oaep_md:{_md(hash_oaep)}",
                     "-pkeyopt", f"rsa_mgf1_md:{_md(hash_oaep)}")
    criptograma = _run("enc", "-aes-256-cbc", "-K", chave.hex(), "-iv", iv.hex(),
                       entrada=TEXTO_EXEMPLO.encode("utf-8"))
    msg_cif = codificar(criptograma, cod)
    (tmp_path / "msg").write_bytes(msg_cif.encode("ascii"))
    assinatura = _run("dgst", f"-{_md(hash_sig)}", "-sign", remetente.privada_pem, tmp_path / "msg")

    env = {
        "parametros": Parametros(hash_oaep, hash_sig, cod).para_json(),
        "envelope": {
            "iv": codificar(iv, cod),
            "chave_sessao": codificar(chave_cif, cod),
            "mensagem_cifrada": msg_cif,
            "assinatura": codificar(assinatura, cod),
        },
    }
    resultado = abrir_envelope(json.loads(json.dumps(env)), destinatario.privada, remetente.publica)
    assert resultado.texto.decode("utf-8") == TEXTO_EXEMPLO
    assert resultado.avisos == []


def test_base64_compativel_com_openssl(remetente, destinatario):
    """O Base64 gerado é o padrão (sem quebras de linha), igual ao 'openssl base64 -A'."""
    dados = os.urandom(300)
    assert _run("base64", "-A", entrada=dados).decode().strip() == base64.b64encode(dados).decode()
