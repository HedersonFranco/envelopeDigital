"""Mensagens padronizadas no terminal (sem cores, para funcionar em qualquer console)."""

from __future__ import annotations

import sys

from .erros import EnvelopeErro


def configurar_console() -> None:
    """Evita UnicodeEncodeError em consoles que não suportam todos os caracteres."""
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass


def ok(mensagem: str) -> None:
    print(f"[OK] {mensagem}")


def info(mensagem: str) -> None:
    print(f"     {mensagem}")


def aviso(mensagem: str) -> None:
    print(f"[AVISO] {mensagem}", file=sys.stderr)


def erro(exc: EnvelopeErro | str) -> None:
    if isinstance(exc, EnvelopeErro):
        print(f"[ERRO] {exc.mensagem}", file=sys.stderr)
        if exc.dica:
            print(f"       Dica: {exc.dica}", file=sys.stderr)
    else:
        print(f"[ERRO] {exc}", file=sys.stderr)
