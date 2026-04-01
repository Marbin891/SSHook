#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_ROOT="$PROJECT_ROOT/app/main.py"
ENV_FILE="${1:-$PROJECT_ROOT/.env}"

if [[ ! -f "$APP_ROOT" ]]; then
  echo "No existe $APP_ROOT" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No existe el archivo de entorno: $ENV_FILE" >&2
  exit 1
fi

python3 "$APP_ROOT" --env-file "$ENV_FILE" --healthcheck

if command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files sshook.service >/dev/null 2>&1; then
    systemctl status sshook.service --no-pager || true
  fi
fi
