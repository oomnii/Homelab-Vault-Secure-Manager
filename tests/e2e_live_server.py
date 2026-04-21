from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]


def wait_until_ready(base_url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(base_url + '/', timeout=1, allow_redirects=False)
            if response.status_code in {200, 302}:
                return
        except requests.RequestException:
            time.sleep(0.25)
    raise RuntimeError('Server did not become ready in time.')


def extract_otp(html: str) -> str:
    match = re.search(r'<span id="dev-otp-value">(\d{6})</span>', html)
    if not match:
        raise RuntimeError('Could not find development OTP in HTML.')
    return match.group(1)


def main() -> int:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = Path(tmpdir) / 'e2e.db'
        env = os.environ.copy()
        env['DATABASE_URL'] = f'sqlite:///{db_path}'
        env['SECRET_KEY'] = 'e2e-secret-key'
        env['PORT'] = '5010'
        env['OTP_DEV_MODE'] = 'true'
        server = subprocess.Popen([sys.executable, 'run.py'], cwd=ROOT, env=env)
        try:
            base = 'http://127.0.0.1:5010'
            wait_until_ready(base)
            session = requests.Session()

            response = session.get(base + '/', allow_redirects=True, timeout=5)
            assert 'Create Master Account' in response.text

            response = session.post(
                base + '/setup',
                data={
                    'username': 'admin',
                    'email': 'admin@example.com',
                    'password': 'supersecure123',
                    'confirm_password': 'supersecure123',
                },
                allow_redirects=True,
                timeout=5,
            )
            assert 'Master account created' in response.text

            response = session.post(
                base + '/login',
                data={'identifier': 'admin', 'password': 'supersecure123'},
                allow_redirects=True,
                timeout=5,
            )
            assert 'Verify Email OTP' in response.text
            otp = extract_otp(response.text)

            response = session.post(
                base + '/verify-otp',
                data={'otp': otp},
                allow_redirects=True,
                timeout=5,
            )
            assert 'Dashboard' in response.text

            response = session.post(
                base + '/folders/create',
                data={'name': 'Banking'},
                allow_redirects=True,
                timeout=5,
            )
            assert 'Folder created' in response.text
            folder_match = re.search(r'/folders/(\d+)/delete', response.text)
            assert folder_match
            folder_id = folder_match.group(1)

            response = session.post(
                base + '/vault/create',
                data={
                    'title': 'Gmail',
                    'website': 'https://gmail.com',
                    'username': 'om@example.com',
                    'password': 'pass12345',
                    'notes': 'mail',
                    'folder_id': folder_id,
                },
                allow_redirects=True,
                timeout=5,
            )
            assert 'Vault item added' in response.text
            item_match = re.search(r'/vault/(\d+)/update', response.text)
            assert item_match and item_match.group(1).isdigit()

            response = session.post(
                base + '/secure-ids/create',
                data={
                    'title': 'Aadhaar',
                    'id_type': 'Aadhaar',
                    'id_value': '1234',
                    'expiry_date': '',
                    'notes': 'govt',
                    'folder_id': folder_id,
                },
                allow_redirects=True,
                timeout=5,
            )
            assert 'Secure ID added' in response.text

            response = session.post(
                base + '/secure-notes/create',
                data={
                    'title': 'Recovery Note',
                    'note_content': 'Primary recovery note body',
                    'folder_id': folder_id,
                },
                allow_redirects=True,
                timeout=5,
            )
            assert 'Secure note added' in response.text

            response = session.post(base + '/backup/export', timeout=5)
            assert response.status_code == 200
            assert 'encrypted-vault-export' in response.text

            response = session.get(base + '/history', timeout=5)
            assert 'Login History' in response.text
            assert 'IST' in response.text

            response = session.post(base + '/logout', allow_redirects=True, timeout=5)
            assert 'logged out' in response.text.lower()
            print('Live server HTTP smoke test passed.')
            return 0
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == '__main__':
    raise SystemExit(main())
