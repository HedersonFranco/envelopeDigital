#!/usr/bin/env python3
"""Gera os arquivos de teste em ``exemplos/gerados/``.

    python scripts/gerar_exemplos.py            # gera (mantém chaves existentes)
    python scripts/gerar_exemplos.py --novas    # recria também as chaves

Conteúdo gerado:
    chaves/                remetente_*, destinatario_* e intruso_* (PEM)
    envelopes/             um envelope para cada uma das 8 combinações de parâmetros
    adulterados/           envelopes com defeitos propositais, para testar o tratamento de erros
"""

from __future__ import annotations

import argparse
import copy
import itertools
import json
import shutil
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "src"))

from envelope_digital import Parametros, criar_envelope, salvar_envelope  # noqa: E402
from envelope_digital.chaves import (  # noqa: E402
    carregar_chave_privada,
    carregar_chave_publica,
    gerar_par_de_chaves,
)

EXEMPLOS = RAIZ / "exemplos"
DESTINO = EXEMPLOS / "gerados"


def _trocar_char(valor: str, pos: int = 20) -> str:
    return valor[:pos] + ("A" if valor[pos] != "A" else "B") + valor[pos + 1:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--novas", action="store_true", help="recria as chaves")
    args = parser.parse_args()

    pasta_chaves = DESTINO / "chaves"
    if args.novas and DESTINO.exists():
        shutil.rmtree(DESTINO)
    for pasta in ("envelopes", "adulterados"):
        if (DESTINO / pasta).exists():
            shutil.rmtree(DESTINO / pasta)

    for nome in ("remetente", "destinatario", "intruso"):
        if not (pasta_chaves / f"{nome}_privada.pem").exists():
            gerar_par_de_chaves(pasta_chaves, nome, sobrescrever=True)

    rem_priv = carregar_chave_privada(pasta_chaves / "remetente_privada.pem")
    dest_pub = carregar_chave_publica(pasta_chaves / "destinatario_publica.pem")
    texto = (EXEMPLOS / "mensagem.txt").read_bytes()

    for hash_oaep, hash_sig, cod in itertools.product(("SHA-256", "SHA-512"), ("SHA-256", "SHA-512"), ("Base64", "Hex")):
        p = Parametros(hash_oaep, hash_sig, cod)
        nome = f"envelope_oaep-{hash_oaep.lower()}_assin-{hash_sig.lower()}_{cod.lower()}.json"
        salvar_envelope(criar_envelope(texto, dest_pub, rem_priv, p), DESTINO / "envelopes" / nome)

    base = criar_envelope(texto, dest_pub, rem_priv, Parametros())
    adulterados = {}

    e = copy.deepcopy(base)
    e["envelope"]["mensagem_cifrada"] = _trocar_char(e["envelope"]["mensagem_cifrada"])
    adulterados["01_criptograma_alterado.json"] = e

    e = copy.deepcopy(base)
    e["envelope"]["assinatura"] = _trocar_char(e["envelope"]["assinatura"])
    adulterados["02_assinatura_alterada.json"] = e

    e = copy.deepcopy(base)
    e["envelope"]["chave_sessao"] = _trocar_char(e["envelope"]["chave_sessao"])
    adulterados["03_chave_sessao_alterada.json"] = e

    e = copy.deepcopy(base)
    e["parametros"]["hash_assinatura"] = "SHA-512"
    adulterados["04_hash_assinatura_divergente.json"] = e

    e = copy.deepcopy(base)
    e["parametros"]["codificacao"] = "Base32"
    adulterados["05_parametro_invalido.json"] = e

    e = copy.deepcopy(base)
    del e["envelope"]["iv"]
    adulterados["06_campo_ausente.json"] = e

    for nome, env in adulterados.items():
        salvar_envelope(env, DESTINO / "adulterados" / nome)
    texto_json = json.dumps(base, indent=4)
    (DESTINO / "adulterados" / "07_json_truncado.json").write_text(texto_json[: len(texto_json) // 2], encoding="utf-8")

    print(f"Exemplos gerados em {DESTINO.relative_to(RAIZ)}/")
    for arquivo in sorted(DESTINO.rglob("*")):
        if arquivo.is_file():
            print("  ", arquivo.relative_to(DESTINO))
    return 0


if __name__ == "__main__":
    sys.exit(main())
