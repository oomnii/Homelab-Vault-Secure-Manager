import os
from pathlib import Path

# Load .env before create_app so Windows/IDE launches (wrong CWD) still see OTP_DEV_MODE and SMTP.
# Project .env overrides instance/.env so the repo root file wins for local dev.
try:
    from dotenv import load_dotenv

    _PROJECT_ROOT = Path(__file__).resolve().parent
    load_dotenv(_PROJECT_ROOT / 'instance' / '.env', override=False)
    load_dotenv(_PROJECT_ROOT / '.env', override=True)
except ImportError:
    pass

from app import create_app

app = create_app()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False)
