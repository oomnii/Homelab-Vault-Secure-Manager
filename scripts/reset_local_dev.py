"""
HL-01 local development reset — removes SQLite vault data only (Windows-safe).

Does NOT delete: source code, tests, .env, instance/.env, requirements, or deployment files.
Stops short if DATABASE_URL points to non-sqlite (e.g. Postgres) unless --force-sqlite-only.

Usage (from project root):
  .\\.venv\\Scripts\\python.exe scripts\\reset_local_dev.py
  .\\.venv\\Scripts\\python.exe scripts\\reset_local_dev.py --yes
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_dotenv(project_root: Path) -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(project_root / 'instance' / '.env', override=False)
    load_dotenv(project_root / '.env', override=True)


def _sqlite_db_candidates(project_root: Path) -> list[Path]:
    """Paths to SQLite database files that may exist (primary + sidecars added separately)."""
    seen: set[Path] = set()
    out: list[Path] = []

    def add(p: Path) -> None:
        try:
            r = p.resolve()
        except OSError:
            r = p
        if r not in seen:
            seen.add(r)
            out.append(r)

    env_url = (os.environ.get('DATABASE_URL') or '').strip()
    if env_url:
        try:
            from sqlalchemy.engine.url import make_url

            u = make_url(env_url)
            if u.drivername == 'sqlite' and u.database and u.database != ':memory:':
                db_path = Path(u.database)
                if not db_path.is_absolute():
                    db_path = (project_root / db_path).resolve()
                add(db_path)
        except Exception:
            pass

    add((project_root / 'instance' / 'vault.db').resolve())

    instance_dir = project_root / 'instance'
    if instance_dir.is_dir():
        for p in instance_dir.glob('*.db'):
            add(p.resolve())

    return out


def _sidecars(db_path: Path) -> list[Path]:
    """SQLite may create -wal and -shm next to the main file."""
    s = str(db_path)
    return [db_path, Path(s + '-wal'), Path(s + '-shm')]


def _collect_existing_files(db_bases: list[Path]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for base in db_bases:
        for p in _sidecars(base):
            if p.exists() and p.is_file():
                try:
                    key = p.resolve()
                except OSError:
                    key = p
                if key not in seen:
                    seen.add(key)
                    found.append(p)
    return sorted(found, key=lambda x: str(x).lower())


def main() -> int:
    parser = argparse.ArgumentParser(description='Reset HL-01 local SQLite vault data (dev only).')
    parser.add_argument(
        '--yes',
        '-y',
        action='store_true',
        help='Skip confirmation prompt (e.g. for automation).',
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Do not copy files to backups/ before deletion (not recommended).',
    )
    parser.add_argument(
        '--force-sqlite-only',
        action='store_true',
        help='Allow run even if DATABASE_URL is set to a non-sqlite URL (only sqlite files are touched).',
    )
    args = parser.parse_args()

    project_root = _project_root()
    os.chdir(project_root)
    _load_dotenv(project_root)

    env_url = (os.environ.get('DATABASE_URL') or '').strip()
    if env_url and not env_url.startswith('sqlite:'):
        if not args.force_sqlite_only:
            print(
                'DATABASE_URL is not SQLite. This script only removes local SQLite vault files.\n'
                'Refusing to continue. Use --force-sqlite-only if you still want to delete instance/*.db only.',
                file=sys.stderr,
            )
            return 2

    db_bases = _sqlite_db_candidates(project_root)
    to_remove = _collect_existing_files(db_bases)

    if not to_remove:
        print('No SQLite vault files found (nothing to reset).')
        print(f'Expected locations: {project_root / "instance" / "vault.db"}')
        print('First-run setup will appear after you start the app and visit /. ')
        return 0

    print('HL-01 local runtime data identified for removal:')
    for p in to_remove:
        print(f'  - {p}')
    print()
    print('Preserved (not deleted): code, tests, .env, instance/.env, export is browser-only (no server copies).')

    if not args.yes:
        reply = input('Type RESET and press Enter to continue (or empty to abort): ').strip()
        if reply != 'RESET':
            print('Aborted.')
            return 1

    if not args.no_backup:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        backup_dir = project_root / 'backups' / f'hl01-local-reset-{stamp}'
        backup_dir.mkdir(parents=True, exist_ok=True)
        meta = backup_dir / 'README.txt'
        meta.write_text(
            'Backup created by scripts/reset_local_dev.py before deleting local SQLite vault data.\n'
            'To restore: stop the app, copy the .db (and -wal/-shm if present) back into instance/.\n',
            encoding='utf-8',
        )
        for p in to_remove:
            dest = backup_dir / p.name
            shutil.copy2(p, dest)
            print(f'Backed up: {p.name} -> {dest}')
        print(f'Backup folder: {backup_dir}')
    else:
        print('Skipping backup (--no-backup).')

    errors = 0
    for p in to_remove:
        try:
            p.unlink()
            print(f'Deleted: {p}')
        except OSError as e:
            print(f'ERROR deleting {p}: {e}', file=sys.stderr)
            errors += 1

    if errors:
        print('Some files could not be deleted. Stop the Flask app and retry.', file=sys.stderr)
        return 3

    print()
    print('Reset complete. Next steps:')
    print('  1. Stop any running dev server, then start again: .\\.venv\\Scripts\\python.exe run.py')
    print('  2. Open http://127.0.0.1:5000 - you should see master account setup (no users in DB).')
    print('  3. Clear site cookies for localhost if an old session cookie causes odd redirects.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
