"""Exceções do projeto.

Todas as falhas previsíveis (arquivo ausente, chave inválida, JSON corrompido,
assinatura que não confere...) são convertidas em subclasses de
``EnvelopeErro``. A interface captura apenas essa hierarquia e mostra a
mensagem ao usuário, sem nunca encerrar com um *stack trace*.
"""

from __future__ import annotations


class EnvelopeErro(Exception):
    """Erro base. ``mensagem`` diz o que houve; ``dica`` sugere como corrigir."""

    codigo_saida = 1

    def __init__(self, mensagem: str, dica: str | None = None) -> None:
        super().__init__(mensagem)
        self.mensagem = mensagem
        self.dica = dica

    def __str__(self) -> str:
        if self.dica:
            return f"{self.mensagem}\n  Dica: {self.dica}"
        return self.mensagem


class ArquivoErro(EnvelopeErro):
    """Falha ao ler ou gravar um arquivo."""


class ChaveInvalidaErro(EnvelopeErro):
    """Arquivo PEM inválido, do tipo errado ou com tamanho insuficiente."""


class ChaveProtegidaErro(ChaveInvalidaErro):
    """A chave privada está protegida por senha e a senha não foi informada."""


class FormatoEnvelopeErro(EnvelopeErro):
    """JSON malformado, campo ausente ou parâmetro não suportado."""


class CodificacaoErro(EnvelopeErro):
    """Campo que não é Base64/Hex válido."""


class EntradaInvalidaErro(EnvelopeErro):
    """Texto de entrada inválido (por exemplo, não é UTF-8)."""


class AssinaturaInvalidaErro(EnvelopeErro):
    """A assinatura do criptograma não confere: integridade violada."""

    codigo_saida = 3


class DecifragemErro(EnvelopeErro):
    """Falha ao decifrar a chave de sessão ou a mensagem."""
