"""
Create the project root .env from .env.example only if .env is missing.

Never overwrites an existing .env. Safe to run after clone, before first run.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dest = root / '.env'
    example = root / '.env.example'

    if dest.exists():
        print('.env already exists; leaving it unchanged.')
        return 0
    if not example.is_file():
        print('ERROR: .env.example not found next to run.py (project root).', file=sys.stderr)
        return 1
    shutil.copy2(example, dest)
    print('Created .env from .env.example. Edit it with real secrets before production use.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
