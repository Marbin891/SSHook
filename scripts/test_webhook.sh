#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${1:-$PROJECT_ROOT/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "No existe el archivo de entorno: $ENV_FILE" >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo "python3 no está instalado o no está en PATH." >&2
  exit 1
}

python3 - "$ENV_FILE" "$(hostname)" <<'PY'
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib import error, request

env_file = Path(sys.argv[1])
default_hostname = sys.argv[2]


def load_env_file(path):
    parsed = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip().strip('"').strip("'")
    return parsed


env_values = load_env_file(env_file)
url = os.environ.get("DISCORD_WEBHOOK_URL", env_values.get("DISCORD_WEBHOOK_URL", "")).strip()
hostname = (
    os.environ.get("HOSTNAME_ALIAS", env_values.get("HOSTNAME_ALIAS", "")).strip()
    or default_hostname
)

if not url:
    print(f"DISCORD_WEBHOOK_URL no está configurado en {env_file}", file=sys.stderr)
    raise SystemExit(1)

timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

payload = {
    "username": "SSHook",
    "embeds": [
        {
            "title": "Prueba de webhook SSHook",
            "color": 0x3498DB,
            "description": f"✅ SSHook puede enviar alertas a Discord desde {hostname} a las {timestamp}.",
            "fields": [
                {"name": "Servidor", "value": hostname, "inline": True},
                {"name": "Hora", "value": timestamp, "inline": True},
                {"name": "Estado", "value": "ok", "inline": True},
            ],
            "footer": {"text": "SSHook | webhook test"},
        }
    ],
}

req = request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "SSHook/0.1 (+https://github.com/Marbin891/SSHook)",
    },
    method="POST",
)

try:
    with request.urlopen(req, timeout=10) as response:
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}")
except error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    print(f"Error HTTP {exc.code}: {body}", file=sys.stderr)
    raise SystemExit(1)
except error.URLError as exc:
    print(f"No se pudo conectar al webhook: {exc}", file=sys.stderr)
    raise SystemExit(1)

print("Webhook enviado correctamente.")
PY
