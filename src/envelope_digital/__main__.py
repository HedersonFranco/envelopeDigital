"""Permite executar com ``python -m envelope_digital``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
