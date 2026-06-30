#!/usr/bin/env bash
cd "$(dirname "$0")"
export PORT=${PORT:-5000}
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
exec ./venv/bin/gunicorn -w 4 -b 0.0.0.0:$PORT app:app
