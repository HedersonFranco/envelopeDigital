#!/usr/bin/env python3
"""Atalho para executar o programa sem instalar o pacote.

    python envelope.py              # menu interativo
    python envelope.py --help       # linha de comando
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from envelope_digital.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
