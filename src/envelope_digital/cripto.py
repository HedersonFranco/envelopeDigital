"""Primitivas criptográficas usadas pelo protocolo.

- AES-256-CBC com padding PKCS#7 (para blocos de 16 bytes, equivale ao PKCS#5);
- RSA-OAEP com MGF1 usando a mesma função de hash do OAEP e sem rótulo (label);
- assinatura RSASSA-PKCS1-v1_5 (compatível com o CyberChef).

As funções recebem e devolvem ``bytes``. Conversões de texto e codificação
ficam a cargo do módulo ``envelope``.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .erros import ChaveInvalidaErro, DecifragemErro, FormatoEnvelopeErro

TAMANHO_CHAVE_AES = 32  # 256 bits
TAMANHO_IV = 16  # 128 bits = tamanho do bloco AES
TAMANHO_BLOCO_BITS = 128

SHA256 = "SHA-256"
SHA512 = "SHA-512"
HASHES = {SHA256: hashes.SHA256, SHA512: hashes.SHA512}


def normalizar_hash(nome: str, parametro: str = "hash") -> str:
    """Aceita ``SHA-256``, ``sha256``, ``SHA_512``... e devolve o nome canônico."""
    if not isinstance(nome, str):
        raise FormatoEnvelopeErro(f"O parâmetro '{parametro}' deve ser um texto.")
    chave = nome.strip().upper().replace("-", "").replace("_", "")
    for canonico in HASHES:
        if chave == canonico.replace("-", ""):
            return canonico
    raise FormatoEnvelopeErro(
        f"Função de hash não suportada em '{parametro}': {nome!r}.",
        "Use \"SHA-256\" ou \"SHA-512\".",
    )


def _hash(nome: str) -> hashes.HashAlgorithm:
    return HASHES[normalizar_hash(nome)]()


# ---------------------------------------------------------------- aleatoriedade
def gerar_chave_sessao() -> bytes:
    """Chave AES-256 aleatória (CSPRNG do sistema operacional)."""
    return os.urandom(TAMANHO_CHAVE_AES)


def gerar_iv() -> bytes:
    """Vetor de inicialização aleatório de 16 bytes."""
    return os.urandom(TAMANHO_IV)


# ---------------------------------------------------------------- AES-256-CBC
def aes_cifrar(chave: bytes, iv: bytes, texto: bytes) -> bytes:
    _checar_aes(chave, iv)
    preenchedor = padding.PKCS7(TAMANHO_BLOCO_BITS).padder()
    dados = preenchedor.update(texto) + preenchedor.finalize()
    cifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return cifrador.update(dados) + cifrador.finalize()


def aes_decifrar(chave: bytes, iv: bytes, criptograma: bytes) -> bytes:
    _checar_aes(chave, iv)
    if not criptograma or len(criptograma) % (TAMANHO_BLOCO_BITS // 8) != 0:
        raise DecifragemErro(
            f"Criptograma com tamanho inválido ({len(criptograma)} bytes).",
            "No modo CBC o criptograma deve ter tamanho múltiplo de 16 bytes.",
        )
    decifrador = Cipher(algorithms.AES(chave), modes.CBC(iv)).decryptor()
    dados = decifrador.update(criptograma) + decifrador.finalize()
    try:
        removedor = padding.PKCS7(TAMANHO_BLOCO_BITS).unpadder()
        return removedor.update(dados) + removedor.finalize()
    except ValueError:
        raise DecifragemErro(
            "Falha ao decifrar a mensagem: padding PKCS#7 inválido.",
            "A chave de sessão ou o IV não correspondem ao criptograma.",
        ) from None


def _checar_aes(chave: bytes, iv: bytes) -> None:
    if len(chave) != TAMANHO_CHAVE_AES:
        raise DecifragemErro(
            f"Chave AES com {len(chave)} bytes; o AES-256 exige {TAMANHO_CHAVE_AES} bytes."
        )
    if len(iv) != TAMANHO_IV:
        raise FormatoEnvelopeErro(
            f"IV com {len(iv)} bytes; o modo CBC exige {TAMANHO_IV} bytes."
        )


# ---------------------------------------------------------------- RSA-OAEP
def _oaep(nome_hash: str) -> rsa_padding.OAEP:
    algoritmo = _hash(nome_hash)
    return rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=algoritmo), algorithm=algoritmo, label=None)


def capacidade_oaep(chave: rsa.RSAPublicKey | rsa.RSAPrivateKey, nome_hash: str) -> int:
    """Máximo de bytes que o RSA-OAEP cifra com essa chave: k - 2*hLen - 2."""
    k = (chave.key_size + 7) // 8
    return k - 2 * _hash(nome_hash).digest_size - 2


def rsa_oaep_cifrar(publica: rsa.RSAPublicKey, dados: bytes, nome_hash: str) -> bytes:
    capacidade = capacidade_oaep(publica, nome_hash)
    if len(dados) > capacidade:
        raise ChaveInvalidaErro(
            f"A chave pública do destinatário ({publica.key_size} bits) só cifra "
            f"{max(capacidade, 0)} bytes com RSA-OAEP/{normalizar_hash(nome_hash)}, "
            f"mas a chave de sessão codificada tem {len(dados)} bytes.",
            "Use uma chave RSA de 2048 bits ou mais, ou o SHA-256 no OAEP.",
        )
    return publica.encrypt(dados, _oaep(nome_hash))


def rsa_oaep_decifrar(privada: rsa.RSAPrivateKey, dados: bytes, nome_hash: str) -> bytes:
    try:
        return privada.decrypt(dados, _oaep(nome_hash))
    except ValueError:
        raise DecifragemErro(
            "Não foi possível decifrar a chave de sessão com RSA-OAEP.",
            "Verifique se está usando a chave privada do DESTINATÁRIO correto "
            "e se 'hash_oaep' corresponde ao usado na cifragem.",
        ) from None


# ---------------------------------------------------------------- assinatura
def assinar(privada: rsa.RSAPrivateKey, dados: bytes, nome_hash: str) -> bytes:
    return privada.sign(dados, rsa_padding.PKCS1v15(), _hash(nome_hash))


def verificar(publica: rsa.RSAPublicKey, dados: bytes, assinatura: bytes, nome_hash: str) -> bool:
    try:
        publica.verify(assinatura, dados, rsa_padding.PKCS1v15(), _hash(nome_hash))
        return True
    except InvalidSignature:
        return False
