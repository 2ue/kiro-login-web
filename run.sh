#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
exec .venv/bin/python app.py --host "${KIRO_LOGIN_HOST:-127.0.0.1}" --port "${KIRO_LOGIN_PORT:-7888}"
