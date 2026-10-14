"""Protocolo do envelope digital assinado (Encrypt-then-Sign).

Criação (remetente)::

    chave, iv       <- aleatórios (32 e 16 bytes)
    chave_txt       <- codificar(chave)                         # Base64/Hex
    chave_sessao    <- codificar(RSA-OAEP(pub_dest, chave_txt))  # cifra o TEXTO codificado
    mensagem_cifrada<- codificar(AES-256-CBC(chave, iv, texto))
    assinatura      <- codificar(RSA-PKCS1v15(priv_rem, mensagem_cifrada))  # assina o TEXTO codificado

Abertura (destinatário): valida o JSON, verifica a assinatura ANTES de
decifrar qualquer coisa, recupera a chave de sessão e decifra a mensagem.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from . import cripto
from .codificacao import BASE64, CODIFICACOES, codificar, decodificar, normalizar_codificacao
from .erros import (
    ArquivoErro,
    AssinaturaInvalidaErro,
    CodificacaoErro,
    DecifragemErro,
    EntradaInvalidaErro,
    FormatoEnvelopeErro,
)

# Valores fixos definidos pelo protocolo.
ALGORITMO_SIMETRICO = "AES-256-CBC"
PADDING_SIMETRICO = "PKCS7"
ALGORITMO_CHAVE = "RSA-OAEP"
ALGORITMO_ASSINATURA = "RSA"

# Variantes aceitas na LEITURA para os campos fixos (comparação sem
# maiúsculas/minúsculas, hífens, sublinhados, '#' e espaços).
_VARIANTES_FIXAS = {
    "algoritmo_simetrico": (ALGORITMO_SIMETRICO, {"aes256cbc"}),
    "padding_simetrico": (PADDING_SIMETRICO, {"pkcs7", "pkcs5"}),
    "algoritmo_chave": (ALGORITMO_CHAVE, {"rsaoaep"}),
    "algoritmo_assinatura": (ALGORITMO_ASSINATURA, {"rsa", "rsapkcs1v15", "rsassapkcs1v15"}),
}

CAMPOS_ENVELOPE = ("iv", "chave_sessao", "mensagem_cifrada", "assinatura")


@dataclass(frozen=True)
class Parametros:
    hash_oaep: str = cripto.SHA256
    hash_assinatura: str = cripto.SHA256
    codificacao: str = BASE64

    def __post_init__(self) -> None:
        object.__setattr__(self, "hash_oaep", cripto.normalizar_hash(self.hash_oaep, "hash_oaep"))
        object.__setattr__(
            self, "hash_assinatura", cripto.normalizar_hash(self.hash_assinatura, "hash_assinatura")
        )
        object.__setattr__(self, "codificacao", normalizar_codificacao(self.codificacao))

    def para_json(self) -> dict[str, str]:
        return {
            "algoritmo_simetrico": ALGORITMO_SIMETRICO,
            "padding_simetrico": PADDING_SIMETRICO,
            "algoritmo_chave": ALGORITMO_CHAVE,
            "hash_oaep": self.hash_oaep,
            "algoritmo_assinatura": ALGORITMO_ASSINATURA,
            "hash_assinatura": self.hash_assinatura,
            "codificacao": self.codificacao,
        }


@dataclass
class ResultadoAbertura:
    """Resultado da abertura: bytes do texto em claro e eventuais avisos."""

    texto: bytes
    parametros: Parametros
    avisos: list[str] = field(default_factory=list)

    def texto_utf8(self) -> str | None:
        try:
            return self.texto.decode("utf-8")
        except UnicodeDecodeError:
            return None


# ============================================================== criação
def criar_envelope(
    mensagem: bytes | str,
    publica_destinatario: rsa.RSAPublicKey,
    privada_remetente: rsa.RSAPrivateKey,
    parametros: Parametros | None = None,
) -> dict[str, Any]:
    """Cria o envelope (dicionário pronto para ``json.dump``)."""
    p = parametros or Parametros()
    if isinstance(mensagem, str):
        mensagem = mensagem.encode("utf-8")

    # 1. Segredos aleatórios
    chave = cripto.gerar_chave_sessao()
    iv = cripto.gerar_iv()

    # 2. Codificação da chave de sessão (o TEXTO resultante é o que vai para o RSA)
    chave_txt = codificar(chave, p.codificacao)

    # 3. Cifragem da chave de sessão com a pública do destinatário
    chave_cifrada = cripto.rsa_oaep_cifrar(publica_destinatario, chave_txt.encode("ascii"), p.hash_oaep)

    # 4. Cifragem da mensagem
    criptograma = cripto.aes_cifrar(chave, iv, mensagem)
    mensagem_cifrada = codificar(criptograma, p.codificacao)

    # 5. Assinatura sobre o criptograma CODIFICADO (Encrypt-then-Sign)
    assinatura = cripto.assinar(privada_remetente, mensagem_cifrada.encode("ascii"), p.hash_assinatura)

    # 6. Montagem
    return {
        "parametros": p.para_json(),
        "envelope": {
            "iv": codificar(iv, p.codificacao),
            "chave_sessao": codificar(chave_cifrada, p.codificacao),
            "mensagem_cifrada": mensagem_cifrada,
            "assinatura": codificar(assinatura, p.codificacao),
        },
    }


# ============================================================== validação
def _compactar(valor: str) -> str:
    return "".join(c for c in valor.lower() if c.isalnum())


def validar_envelope(dados: Any) -> tuple[Parametros, dict[str, str], list[str]]:
    """Valida a estrutura do JSON e devolve (parâmetros, campos do envelope, avisos)."""
    avisos: list[str] = []
    if not isinstance(dados, dict):
        raise FormatoEnvelopeErro("O JSON do envelope deve ser um objeto { ... }.")
    params = dados.get("parametros")
    env = dados.get("envelope")
    if not isinstance(params, dict):
        raise FormatoEnvelopeErro("Seção 'parametros' ausente ou inválida no envelope.")
    if not isinstance(env, dict):
        raise FormatoEnvelopeErro("Seção 'envelope' ausente ou inválida no envelope.")

    for nome, (esperado, aceitos) in _VARIANTES_FIXAS.items():
        valor = params.get(nome)
        if valor is None:
            avisos.append(f"Parâmetro '{nome}' ausente; assumindo \"{esperado}\".")
            continue
        if not isinstance(valor, str) or _compactar(valor) not in aceitos:
            raise FormatoEnvelopeErro(
                f"Valor não suportado em 'parametros.{nome}': {valor!r}.",
                f"Este protocolo usa apenas \"{esperado}\".",
            )

    obrigatorios = ("hash_oaep", "hash_assinatura", "codificacao")
    faltando = [n for n in obrigatorios if n not in params]
    if faltando:
        raise FormatoEnvelopeErro(
            "Parâmetro(s) obrigatório(s) ausente(s): " + ", ".join(f"'{n}'" for n in faltando) + ".",
            f"Valores possíveis: hash = {' ou '.join(cripto.HASHES)}; "
            f"codificacao = {' ou '.join(CODIFICACOES)}.",
        )
    parametros = Parametros(params["hash_oaep"], params["hash_assinatura"], params["codificacao"])

    campos: dict[str, str] = {}
    for nome in CAMPOS_ENVELOPE:
        valor = env.get(nome)
        if valor is None:
            raise FormatoEnvelopeErro(f"Campo obrigatório 'envelope.{nome}' ausente.")
        if not isinstance(valor, str) or not valor.strip():
            raise FormatoEnvelopeErro(f"Campo 'envelope.{nome}' deve ser um texto não vazio.")
        campos[nome] = valor
    return parametros, campos, avisos


# ============================================================== abertura
def verificar_assinatura(dados: Any, publica_remetente: rsa.RSAPublicKey) -> list[str]:
    """Verifica a assinatura do envelope. Lança ``AssinaturaInvalidaErro`` se não conferir.

    Devolve a lista de avisos (vazia quando tudo segue o protocolo à risca).
    """
    p, campos, avisos = validar_envelope(dados)
    _verificar(p, campos, publica_remetente, avisos)
    return avisos


def _verificar(p: Parametros, campos: dict[str, str], publica: rsa.RSAPublicKey, avisos: list[str]) -> None:
    assinatura = decodificar(campos["assinatura"], p.codificacao, "envelope.assinatura")
    msg_codificada = campos["mensagem_cifrada"].encode("utf-8")
    if cripto.verificar(publica, msg_codificada, assinatura, p.hash_assinatura):
        return

    # Compatibilidade: alguns programas assinam os bytes brutos do criptograma.
    try:
        bruto = decodificar(campos["mensagem_cifrada"], p.codificacao, "envelope.mensagem_cifrada")
    except CodificacaoErro:
        bruto = None
    if bruto is not None and cripto.verificar(publica, bruto, assinatura, p.hash_assinatura):
        avisos.append(
            "Compatibilidade: a assinatura foi feita sobre os bytes BRUTOS do criptograma, "
            "e não sobre o texto codificado como define o protocolo."
        )
        return

    raise AssinaturaInvalidaErro(
        "INTEGRIDADE VIOLADA: a assinatura digital do criptograma não confere.",
        "O envelope foi alterado, a chave pública não é a do REMETENTE, "
        "ou 'hash_assinatura' não corresponde ao usado na assinatura. "
        "Nada foi decifrado.",
    )


def _recuperar_chave_sessao(texto: bytes, p: Parametros, avisos: list[str]) -> bytes:
    """Interpreta a saída do RSA: o protocolo prevê a chave CODIFICADA em texto."""
    tentativas = [p.codificacao] + [c for c in CODIFICACOES if c != p.codificacao]
    try:
        como_texto = texto.decode("ascii")
    except UnicodeDecodeError:
        como_texto = None

    if como_texto is not None:
        for cod in tentativas:
            try:
                chave = decodificar(como_texto, cod, "chave de sessão")
            except CodificacaoErro:
                continue
            if len(chave) == cripto.TAMANHO_CHAVE_AES:
                if cod != p.codificacao:
                    avisos.append(
                        f"Compatibilidade: a chave de sessão estava em {cod}, "
                        f"mas o envelope declara {p.codificacao}."
                    )
                return chave

    if len(texto) == cripto.TAMANHO_CHAVE_AES:
        avisos.append(
            "Compatibilidade: a chave de sessão foi cifrada em bytes BRUTOS, "
            "e não codificada em texto como define o protocolo."
        )
        return texto

    raise DecifragemErro(
        f"A chave de sessão decifrada não é uma chave AES-256 válida ({len(texto)} bytes).",
        f"Esperava-se o texto {p.codificacao} de uma chave de 32 bytes.",
    )


def abrir_envelope(
    dados: Any,
    privada_destinatario: rsa.RSAPrivateKey,
    publica_remetente: rsa.RSAPublicKey,
) -> ResultadoAbertura:
    """Abre o envelope seguindo o protocolo Encrypt-then-Sign."""
    # 1. Validação e leitura
    p, campos, avisos = validar_envelope(dados)

    # 2. Verificação da assinatura ANTES de qualquer decifragem
    _verificar(p, campos, publica_remetente, avisos)

    # 3. Recuperação da chave de sessão
    chave_cifrada = decodificar(campos["chave_sessao"], p.codificacao, "envelope.chave_sessao")
    chave_txt = cripto.rsa_oaep_decifrar(privada_destinatario, chave_cifrada, p.hash_oaep)
    chave = _recuperar_chave_sessao(chave_txt, p, avisos)

    # 4. Decifragem da mensagem
    iv = decodificar(campos["iv"], p.codificacao, "envelope.iv")
    if len(iv) != cripto.TAMANHO_IV:
        raise FormatoEnvelopeErro(
            f"O IV tem {len(iv)} bytes; o AES-CBC exige {cripto.TAMANHO_IV} bytes."
        )
    criptograma = decodificar(campos["mensagem_cifrada"], p.codificacao, "envelope.mensagem_cifrada")
    texto = cripto.aes_decifrar(chave, iv, criptograma)
    return ResultadoAbertura(texto=texto, parametros=p, avisos=avisos)


# ============================================================== arquivos
def ler_texto(caminho: str | Path) -> bytes:
    """Lê o arquivo de entrada e confirma que é texto UTF-8 (os bytes são preservados)."""
    caminho = Path(caminho)
    if not caminho.is_file():
        raise ArquivoErro(f"Arquivo de entrada não encontrado: {caminho}")
    try:
        dados = caminho.read_bytes()
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível ler {caminho}: {exc.strerror}") from None
    try:
        dados.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EntradaInvalidaErro(
            f"O arquivo {caminho} não é texto UTF-8 (byte inválido na posição {exc.start}).",
            "Salve o arquivo com a codificação UTF-8 no seu editor.",
        ) from None
    return dados


def salvar_envelope(envelope: dict[str, Any], caminho: str | Path) -> Path:
    caminho = Path(caminho)
    try:
        if caminho.parent and not caminho.parent.exists():
            caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho.write_text(json.dumps(envelope, indent=4, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível gravar o envelope em {caminho}: {exc.strerror}") from None
    return caminho


def carregar_envelope(caminho: str | Path) -> dict[str, Any]:
    caminho = Path(caminho)
    if not caminho.is_file():
        raise ArquivoErro(f"Arquivo de envelope não encontrado: {caminho}")
    try:
        conteudo = caminho.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        raise FormatoEnvelopeErro(f"O envelope {caminho} não é um arquivo de texto UTF-8.") from None
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível ler {caminho}: {exc.strerror}") from None
    try:
        dados = json.loads(conteudo)
    except json.JSONDecodeError as exc:
        raise FormatoEnvelopeErro(
            f"O envelope {caminho} não é um JSON válido (linha {exc.lineno}, coluna {exc.colno}: {exc.msg}).",
            "Confira se o arquivo não foi truncado ou editado manualmente.",
        ) from None
    if not isinstance(dados, dict):
        raise FormatoEnvelopeErro("O JSON do envelope deve ser um objeto { ... }.")
    return dados


def salvar_texto(dados: bytes, caminho: str | Path) -> Path:
    caminho = Path(caminho)
    try:
        if caminho.parent and not caminho.parent.exists():
            caminho.parent.mkdir(parents=True, exist_ok=True)
        caminho.write_bytes(dados)
    except OSError as exc:
        raise ArquivoErro(f"Não foi possível gravar {caminho}: {exc.strerror}") from None
    return caminho
