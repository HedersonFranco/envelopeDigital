"""Operações de alto nível compartilhadas pela linha de comando e pelo menu.

Cada função recebe caminhos de arquivos, executa o protocolo e devolve um
resumo. Erros previsíveis são lançados como ``EnvelopeErro``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import chaves
from .envelope import (
    Parametros,
    ResultadoAbertura,
    abrir_envelope,
    carregar_envelope,
    criar_envelope,
    ler_texto,
    salvar_envelope,
    salvar_texto,
    verificar_assinatura,
)


@dataclass
class ResumoCifragem:
    saida: Path
    parametros: Parametros
    tamanho_texto: int


def gerar_chaves(pasta: str | Path, nome: str, bits: int = 2048, senha: str | None = None,
                 sobrescrever: bool = False) -> tuple[Path, Path]:
    return chaves.gerar_par_de_chaves(pasta, nome, bits=bits, senha=senha, sobrescrever=sobrescrever)


def cifrar(
    *,
    pub_destinatario: str | Path,
    priv_remetente: str | Path,
    saida: str | Path,
    entrada: str | Path | None = None,
    texto: str | None = None,
    parametros: Parametros | None = None,
    senha: str | None = None,
) -> ResumoCifragem:
    """Cria o envelope a partir de um arquivo (``entrada``) ou de um texto digitado."""
    if (entrada is None) == (texto is None):
        raise ValueError("Informe exatamente um entre 'entrada' e 'texto'.")
    mensagem = ler_texto(entrada) if entrada is not None else texto.encode("utf-8")
    publica = chaves.carregar_chave_publica(pub_destinatario, "chave pública do destinatário")
    privada = chaves.carregar_chave_privada(priv_remetente, senha, "chave privada do remetente")
    p = parametros or Parametros()
    env = criar_envelope(mensagem, publica, privada, p)
    caminho = salvar_envelope(env, saida)
    return ResumoCifragem(saida=caminho, parametros=p, tamanho_texto=len(mensagem))


def decifrar(
    *,
    envelope: str | Path,
    priv_destinatario: str | Path,
    pub_remetente: str | Path,
    saida: str | Path | None,
    senha: str | None = None,
) -> ResultadoAbertura:
    """Abre o envelope e, se ``saida`` for informada, grava o texto em claro."""
    dados = carregar_envelope(envelope)
    publica = chaves.carregar_chave_publica(pub_remetente, "chave pública do remetente")
    privada = chaves.carregar_chave_privada(priv_destinatario, senha, "chave privada do destinatário")
    resultado = abrir_envelope(dados, privada, publica)
    if saida is not None:
        salvar_texto(resultado.texto, saida)
    return resultado


def verificar(*, envelope: str | Path, pub_remetente: str | Path) -> list[str]:
    """Só verifica a assinatura (não precisa da chave privada do destinatário)."""
    dados = carregar_envelope(envelope)
    publica = chaves.carregar_chave_publica(pub_remetente, "chave pública do remetente")
    return verificar_assinatura(dados, publica)
