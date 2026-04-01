#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/sshook"
SERVICE_TARGET="/etc/systemd/system/sshook.service"
PURGE_STATE=false

usage() {
  cat <<'USAGE'
Uso: sudo ./scripts/uninstall.sh [--purge-state]

Opciones:
  --purge-state   Borra también /var/lib/sshook y /var/log/sshook
USAGE
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Este script requiere sudo o root." >&2
    exit 1
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --purge-state)
        PURGE_STATE=true
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Argumento no reconocido: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

main() {
  require_root
  parse_args "$@"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now sshook.service >/dev/null 2>&1 || true
    systemctl daemon-reload || true
  fi

  rm -f "$SERVICE_TARGET"
  rm -rf "$INSTALL_DIR"

  if [[ "$PURGE_STATE" == true ]]; then
    rm -rf /var/lib/sshook /var/log/sshook
  fi

  echo "SSHook desinstalado."
  if [[ "$PURGE_STATE" == false ]]; then
    echo "Se conservaron /var/lib/sshook y /var/log/sshook."
  fi
}

main "$@"
