#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_FILE="$PROJECT_ROOT/config/.env.example"
TARGET_FILE="$PROJECT_ROOT/.env"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "No existe $SOURCE_FILE" >&2
  exit 1
fi

if [[ -f "$TARGET_FILE" ]]; then
  echo "$TARGET_FILE ya existe. No se sobrescribirá." >&2
  exit 1
fi

cp "$SOURCE_FILE" "$TARGET_FILE"
chmod 0600 "$TARGET_FILE"
echo "Archivo creado: $TARGET_FILE"
