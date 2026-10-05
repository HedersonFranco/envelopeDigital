#!/usr/bin/env python3
"""Gera o arquivo .zip para entrega no SIGAA.

    python scripts/empacotar_entrega.py

O pacote contém todo o código-fonte, os testes, a documentação (README.md) e os arquivos
de teste de ``exemplos/gerados/``, que são criados automaticamente se ainda não existirem.
Ficam de fora os arquivos de ambiente e de uso local (.git, .venv, caches, chaves e envelopes
criados na raiz durante testes manuais).
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
NOME_PASTA = "envelope-digital-assinado"
SAIDA = RAIZ / "dist" / "Trabalho01_Envelope_Digital_Assinado.zip"

IGNORAR_PASTAS = {".git", ".github", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build", ".idea", ".vscode"}
IGNORAR_NA_RAIZ = {"chaves", "envelope.json", "mensagem_decifrada.txt"}
IGNORAR_SUFIXOS = (".pyc", ".pyo", ".egg-info")
IGNORAR_NOMES = {".DS_Store", "Thumbs.db"}


def _incluir(relativo: Path) -> bool:
    partes = relativo.parts
    if partes[0] in IGNORAR_NA_RAIZ:
        return False
    if any(p in IGNORAR_PASTAS or p.endswith(".egg-info") for p in partes):
        return False
    return relativo.name not in IGNORAR_NOMES and not relativo.name.endswith(IGNORAR_SUFIXOS)


def main() -> int:
    if not (RAIZ / "exemplos" / "gerados" / "envelopes").exists():
        print("Gerando exemplos/gerados/ ...")
        subprocess.run([sys.executable, str(RAIZ / "scripts" / "gerar_exemplos.py")], check=True)

    SAIDA.parent.mkdir(exist_ok=True)
    arquivos = sorted(p for p in RAIZ.rglob("*") if p.is_file() and _incluir(p.relative_to(RAIZ)))
    with zipfile.ZipFile(SAIDA, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arquivo in arquivos:
            zf.write(arquivo, Path(NOME_PASTA) / arquivo.relative_to(RAIZ))

    print(f"Pacote de entrega criado: {SAIDA.relative_to(RAIZ)} ({len(arquivos)} arquivos, "
          f"{SAIDA.stat().st_size / 1024:.0f} KiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
