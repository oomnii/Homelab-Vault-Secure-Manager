from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import Error, expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BASE_URL = os.environ.get('BASE_URL', 'http://127.0.0.1:5010')
PORT = os.environ.get('PORT', '5010')


def wait_until_ready(timeout: float = 20.0) -> None:
    import requests

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = requests.get(BASE_URL + '/', timeout=1, allow_redirects=False)
            if response.status_code in {200, 302}:
                return
        except requests.RequestException:
            time.sleep(0.25)
    raise RuntimeError('Server did not become ready in time.')


def chromium_executable() -> str | None:
    for candidate in ('chromium', 'chromium-browser', 'google-chrome', 'chrome'):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def main() -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / 'playwright.db'
        env = os.environ.copy()
        env['DATABASE_URL'] = f'sqlite:///{db_path}'
        env['SECRET_KEY'] = 'playwright-secret-key'
        env['PORT'] = PORT
        env['OTP_DEV_MODE'] = 'true'
        server = subprocess.Popen([sys.executable, 'run.py'], cwd=ROOT, env=env)
        try:
            wait_until_ready()
            executable_path = chromium_executable()
            launch_kwargs = {'headless': True, 'args': ['--no-sandbox']}
            if executable_path:
                launch_kwargs['executable_path'] = executable_path

            with sync_playwright() as p:
                browser = p.chromium.launch(**launch_kwargs)
                page = browser.new_page()
                try:
                    page.goto(BASE_URL + '/', wait_until='domcontentloaded', timeout=10000)
                except Error as exc:
                    if 'ERR_BLOCKED_BY_ADMINISTRATOR' in str(exc):
                        raise RuntimeError(
                            'Chromium navigation is blocked by this environment policy. '
                            'Run this script on your laptop or Raspberry Pi to perform full browser automation.'
                        ) from exc
                    raise

                expect(page.locator('h1')).to_have_text('Create Master Account')
                page.locator('input[name="username"]').fill('admin')
                page.locator('input[name="email"]').fill('admin@example.com')
                page.locator('input[name="password"]').fill('supersecure123')
                page.locator('input[name="confirm_password"]').fill('supersecure123')
                page.get_by_role('button', name='Create Master Account').click()

                expect(page.locator('h1')).to_have_text('Sign in to Homelab Vault')
                page.locator('input[name="identifier"]').fill('admin')
                page.locator('input[name="password"]').fill('supersecure123')
                page.get_by_role('button', name='Verify Password').click()
                expect(page.locator('h1')).to_have_text('Verify Email OTP')
                otp = page.locator('#dev-otp-value').inner_text()
                page.locator('input[name="otp"]').fill(otp)
                page.get_by_role('button', name='Verify OTP & Unlock Vault').click()
                expect(page.locator('h1')).to_have_text('Dashboard')
                browser.close()
            print('Playwright browser test passed.')
            return 0
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == '__main__':
    raise SystemExit(main())
