#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/sshook"
SERVICE_SOURCE="$PROJECT_ROOT/services/sshook.service"
SERVICE_TARGET="/etc/systemd/system/sshook.service"
SERVICE_DROPIN_DIR="/etc/systemd/system/sshook.service.d"
SERVICE_PATHS_DROPIN="$SERVICE_DROPIN_DIR/paths.conf"
ENV_SOURCE="$PROJECT_ROOT/.env"
SSHOOK_USER="sshook"
SSHOOK_GROUP="sshook"

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
  local parsed

  parsed="$(python3 - "$env_file" <<'PY'
import sys
from pathlib import Path

env_file = Path(sys.argv[1])
values = {
    "STATE_DIR": "/var/lib/sshook",
    "LOG_DIR": "/var/log/sshook",
}
roots = {
    "STATE_DIR": Path("/var/lib/sshook"),
    "LOG_DIR": Path("/var/log/sshook"),
}

for raw_line in env_file.read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip().strip('"').strip("'")
    if key in values and value:
        values[key] = value

for key, value in values.items():
    path = Path(value).expanduser().resolve(strict=False)
    if not path.is_absolute():
        raise SystemExit(f"{key} debe ser una ruta absoluta.")
    try:
        path.relative_to(roots[key])
    except ValueError as exc:
        raise SystemExit(f"{key} debe estar dentro de {roots[key]}.") from exc
    print(f"{key}={path}")
PY
)"

  while IFS="=" read -r key value; do
    case "$key" in
      STATE_DIR) STATE_DIR="$value" ;;
      LOG_DIR) LOG_DIR="$value" ;;
    esac
  done <<< "$parsed"
}

create_service_user() {
  local nologin_shell="/usr/sbin/nologin"

  if [[ -x "$nologin_shell" ]]; then
    :
  elif [[ -x "/sbin/nologin" ]]; then
    nologin_shell="/sbin/nologin"
  else
    nologin_shell="/bin/false"
  fi

  if ! getent group "$SSHOOK_GROUP" >/dev/null; then
    groupadd --system "$SSHOOK_GROUP"
  fi

  if ! id -u "$SSHOOK_USER" >/dev/null 2>&1; then
    useradd \
      --system \
      --no-create-home \
      --home-dir /nonexistent \
      --shell "$nologin_shell" \
      --gid "$SSHOOK_GROUP" \
      "$SSHOOK_USER"
  fi

  for log_group in adm systemd-journal; do
    if getent group "$log_group" >/dev/null; then
      usermod -a -G "$log_group" "$SSHOOK_USER"
    fi
  done
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

  chown -R root:root "$INSTALL_DIR"
  chown root:"$SSHOOK_GROUP" "$INSTALL_DIR/.env"
  chmod 0755 "$INSTALL_DIR"
  chmod 0640 "$INSTALL_DIR/.env"
}

install_service() {
  cp "$SERVICE_SOURCE" "$SERVICE_TARGET"
  chmod 0644 "$SERVICE_TARGET"

  mkdir -p "$SERVICE_DROPIN_DIR"
  cat > "$SERVICE_PATHS_DROPIN" <<EOF
[Service]
ReadWritePaths=$STATE_DIR $LOG_DIR
EOF
  chmod 0644 "$SERVICE_PATHS_DROPIN"

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
  create_service_user
  copy_project

  mkdir -p "$STATE_DIR" "$LOG_DIR"
  if [[ -L "$STATE_DIR" || -L "$LOG_DIR" ]]; then
    echo "STATE_DIR y LOG_DIR no pueden ser symlinks." >&2
    exit 1
  fi
  chown -R "$SSHOOK_USER:$SSHOOK_GROUP" "$STATE_DIR" "$LOG_DIR"
  chmod 0750 "$STATE_DIR" "$LOG_DIR"

  install_service

  echo "Instalación completada."
  echo "Siguientes pasos:"
  echo "  sudo systemctl enable --now sshook.service"
  echo "  sudo systemctl status sshook.service"
}

main "$@"
