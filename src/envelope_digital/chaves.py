"""Leitura, validação e geração de chaves RSA em arquivos PEM."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .erros import ArquivoErro, ChaveInvalidaErro, ChaveProtegidaErro

TAMANHO_MINIMO_BITS = 2048
TAMANHO_PADRAO_BITS = 2048


def _ler_pem(caminho: str | Path, descricao: str) -> bytes:
    caminho = Path(caminho)
    if not caminho.exists():
        raise ArquivoErro(
            f"Arquivo da {descricao} não encontrado: {caminho}",
            "Confira o caminho informado ou gere as chaves com o comando 'gerar-chaves'.",
        )
    if caminho.is_dir():
        raise ArquivoErro(f"O caminho da {descricao} é uma pasta, não um arquivo: {caminho}")
    try:
        dados = caminho.read_bytes()
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível ler a {descricao} ({caminho}): {exc.strerror}") from None
    if b"-----BEGIN" not in dados:
        raise ChaveInvalidaErro(
            f"O arquivo {caminho} não está no formato PEM.",
            "Um arquivo PEM começa com '-----BEGIN ...-----'.",
        )
    return dados


def _validar_rsa(chave, caminho: str | Path, descricao: str) -> None:
    if not isinstance(chave, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        raise ChaveInvalidaErro(
            f"A {descricao} em {caminho} não é uma chave RSA.",
            "Este programa usa apenas RSA (por exemplo, gerada com "
            "'openssl genpkey -algorithm RSA').",
        )


def carregar_chave_publica(caminho: str | Path, descricao: str = "chave pública") -> rsa.RSAPublicKey:
    """Carrega uma chave pública RSA (SubjectPublicKeyInfo ou PKCS#1) em PEM."""
    dados = _ler_pem(caminho, descricao)
    if b"PRIVATE KEY" in dados:
        raise ChaveInvalidaErro(
            f"O arquivo {caminho} contém uma chave PRIVADA, mas era esperada a {descricao}.",
            "Extraia a pública com 'openssl pkey -in privada.pem -pubout -out publica.pem'.",
        )
    try:
        chave = serialization.load_pem_public_key(dados)
    except (ValueError, UnsupportedAlgorithm):
        raise ChaveInvalidaErro(
            f"Não foi possível interpretar a {descricao} em {caminho}.",
            "O arquivo pode estar corrompido ou não ser uma chave pública.",
        ) from None
    _validar_rsa(chave, caminho, descricao)
    return chave


def carregar_chave_privada(
    caminho: str | Path,
    senha: str | None = None,
    descricao: str = "chave privada",
) -> rsa.RSAPrivateKey:
    """Carrega uma chave privada RSA em PEM, opcionalmente protegida por senha."""
    dados = _ler_pem(caminho, descricao)
    if b"PRIVATE KEY" not in dados:
        raise ChaveInvalidaErro(
            f"O arquivo {caminho} não contém uma chave privada, mas era esperada a {descricao}.",
            "Verifique se não trocou a chave pública pela privada.",
        )
    senha_bytes = senha.encode("utf-8") if senha else None
    try:
        chave = serialization.load_pem_private_key(dados, password=senha_bytes)
    except TypeError:
        # Lançado quando a chave exige senha e ela não foi informada (ou vice-versa).
        if senha_bytes is None:
            raise ChaveProtegidaErro(
                f"A {descricao} em {caminho} está protegida por senha.",
                "Informe a senha (opção --pedir-senha na linha de comando).",
            ) from None
        raise ChaveInvalidaErro(
            f"A {descricao} em {caminho} não é protegida por senha.",
            "Execute novamente sem informar senha.",
        ) from None
    except (ValueError, UnsupportedAlgorithm):
        if senha_bytes is not None:
            raise ChaveInvalidaErro(
                f"Não foi possível abrir a {descricao} em {caminho}.",
                "A senha pode estar incorreta ou o arquivo corrompido.",
            ) from None
        raise ChaveInvalidaErro(
            f"Não foi possível interpretar a {descricao} em {caminho}.",
            "O arquivo pode estar corrompido.",
        ) from None
    _validar_rsa(chave, caminho, descricao)
    return chave


def gerar_par_de_chaves(
    pasta: str | Path,
    nome: str,
    bits: int = TAMANHO_PADRAO_BITS,
    senha: str | None = None,
    sobrescrever: bool = False,
) -> tuple[Path, Path]:
    """Gera ``<nome>_privada.pem`` e ``<nome>_publica.pem`` na pasta indicada.

    Os arquivos seguem os mesmos formatos do OpenSSL: PKCS#8 para a privada e
    SubjectPublicKeyInfo para a pública.
    """
    if bits < TAMANHO_MINIMO_BITS:
        raise ChaveInvalidaErro(
            f"Tamanho de chave muito pequeno: {bits} bits.",
            f"Use pelo menos {TAMANHO_MINIMO_BITS} bits.",
        )
    if not nome or any(c in nome for c in '/\\:*?"<>|'):
        raise ArquivoErro(f"Nome inválido para o par de chaves: {nome!r}.")

    pasta = Path(pasta)
    caminho_priv = pasta / f"{nome}_privada.pem"
    caminho_pub = pasta / f"{nome}_publica.pem"
    if not sobrescrever:
        existentes = [str(p) for p in (caminho_priv, caminho_pub) if p.exists()]
        if existentes:
            raise ArquivoErro(
                "Já existem chaves com esse nome: " + ", ".join(existentes),
                "Escolha outro nome ou use --sobrescrever.",
            )

    privada = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    criptografia = (
        serialization.BestAvailableEncryption(senha.encode("utf-8"))
        if senha
        else serialization.NoEncryption()
    )
    pem_priv = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=criptografia,
    )
    pem_pub = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        pasta.mkdir(parents=True, exist_ok=True)
        caminho_priv.write_bytes(pem_priv)
        caminho_pub.write_bytes(pem_pub)
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível gravar as chaves em {pasta}: {exc.strerror}") from None
    try:
        caminho_priv.chmod(0o600)
    except OSError:
        pass
    return caminho_priv, caminho_pub
