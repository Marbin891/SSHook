#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/sshook"
SERVICE_SOURCE="$PROJECT_ROOT/services/sshook.service"
SERVICE_TARGET="/etc/systemd/system/sshook.service"
ENV_SOURCE="$PROJECT_ROOT/.env"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Este script requiere sudo o root porque instala archivos en /opt y /etc/systemd/system." >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Falta el archivo requerido: $path" >&2
    exit 1
  fi
}

load_env_defaults() {
  local env_file="$1"
  set -a
  # shellcheck disable=SC1090
  . "$env_file"
  set +a

  STATE_DIR="${STATE_DIR:-/var/lib/sshook}"
  LOG_DIR="${LOG_DIR:-/var/log/sshook}"
}

copy_project() {
  mkdir -p "$INSTALL_DIR"
  rm -rf "$INSTALL_DIR/app" "$INSTALL_DIR/config" "$INSTALL_DIR/scripts" "$INSTALL_DIR/services" "$INSTALL_DIR/samples"

  cp -R "$PROJECT_ROOT/app" "$INSTALL_DIR/"
  cp -R "$PROJECT_ROOT/config" "$INSTALL_DIR/"
  cp -R "$PROJECT_ROOT/scripts" "$INSTALL_DIR/"
  cp -R "$PROJECT_ROOT/services" "$INSTALL_DIR/"
  cp -R "$PROJECT_ROOT/samples" "$INSTALL_DIR/"
  cp "$PROJECT_ROOT/README.md" "$INSTALL_DIR/"
  cp "$PROJECT_ROOT/requirements.txt" "$INSTALL_DIR/"
  cp "$PROJECT_ROOT/pyproject.toml" "$INSTALL_DIR/"
  cp "$ENV_SOURCE" "$INSTALL_DIR/.env"
}

install_service() {
  cp "$SERVICE_SOURCE" "$SERVICE_TARGET"
  chmod 0644 "$SERVICE_TARGET"
  systemctl daemon-reload
}

main() {
  require_root
  require_file "$ENV_SOURCE"
  require_file "$SERVICE_SOURCE"
  command -v python3 >/dev/null 2>&1 || {
    echo "python3 no está instalado." >&2
    exit 1
  }
  command -v systemctl >/dev/null 2>&1 || {
    echo "systemctl no está disponible. Este script debe ejecutarse en un host Linux con systemd." >&2
    exit 1
  }

  load_env_defaults "$ENV_SOURCE"

  echo "Instalando SSHook en $INSTALL_DIR"
  copy_project

  mkdir -p "$STATE_DIR" "$LOG_DIR"
  chmod 0750 "$STATE_DIR" "$LOG_DIR"

  install_service

  echo "Instalación completada."
  echo "Siguientes pasos:"
  echo "  sudo systemctl enable --now sshook.service"
  echo "  sudo systemctl status sshook.service"
}

main "$@"
