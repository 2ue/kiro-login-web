#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ -f data/mihomo/env ]]; then
  set -a
  # shellcheck disable=SC1091
  source data/mihomo/env
  set +a
fi
exec .venv/bin/python app.py --host "${KIRO_LOGIN_HOST:-0.0.0.0}" --port "${KIRO_LOGIN_PORT:-7888}"
