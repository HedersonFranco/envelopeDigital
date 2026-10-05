"""Fixtures compartilhadas: pares de chaves gerados uma única vez por sessão de testes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from envelope_digital.chaves import carregar_chave_privada, carregar_chave_publica, gerar_par_de_chaves


@dataclass
class Par:
    privada_pem: Path
    publica_pem: Path

    @property
    def privada(self):
        return carregar_chave_privada(self.privada_pem)

    @property
    def publica(self):
        return carregar_chave_publica(self.publica_pem)


@pytest.fixture(scope="session")
def pasta_chaves(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("chaves")


@pytest.fixture(scope="session")
def remetente(pasta_chaves) -> Par:
    return Par(*gerar_par_de_chaves(pasta_chaves, "remetente"))


@pytest.fixture(scope="session")
def destinatario(pasta_chaves) -> Par:
    return Par(*gerar_par_de_chaves(pasta_chaves, "destinatario"))


@pytest.fixture(scope="session")
def intruso(pasta_chaves) -> Par:
    """Terceiro par, usado para simular chaves erradas."""
    return Par(*gerar_par_de_chaves(pasta_chaves, "intruso"))


TEXTO_EXEMPLO = "Olá, professor! Mensagem com acentuação (ç, ã, é), símbolos ✓ e emoji 🔐.\nSegunda linha."
