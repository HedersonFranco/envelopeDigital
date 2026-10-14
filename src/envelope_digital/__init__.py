"""Envelope Digital Assinado: AES-256-CBC + RSA-OAEP + assinatura RSA (Encrypt-then-Sign)."""

from .envelope import (
    Parametros,
    ResultadoAbertura,
    abrir_envelope,
    carregar_envelope,
    criar_envelope,
    salvar_envelope,
    verificar_assinatura,
)
from .erros import EnvelopeErro

__version__ = "1.0.0"

__all__ = [
    "EnvelopeErro",
    "Parametros",
    "ResultadoAbertura",
    "abrir_envelope",
    "carregar_envelope",
    "criar_envelope",
    "salvar_envelope",
    "verificar_assinatura",
    "__version__",
]
