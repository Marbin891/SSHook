from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ENV_FILE = Path(".env")
DEFAULT_AUTH_LOG = Path("/var/log/auth.log")
DEFAULT_SECURE_LOG = Path("/var/log/secure")


class ConfigError(ValueError):
    """Raised when the runtime configuration is invalid."""


@dataclass(slots=True)
class Settings:
    discord_webhook_url: str
    hostname_alias: str
    ssh_log_mode: str
    ssh_journal_units: tuple[str, ...]
    ssh_log_file: str | None
    ssh_poll_interval: float
    ssh_ignore_ips: frozenset[str]
    ssh_ignore_users: frozenset[str]
    ssh_rate_limit_window: int
    ssh_rate_limit_burst: int
    state_dir: Path
    log_dir: Path
    log_level: str
    env_file: Path

    @property
    def dedupe_ttl(self) -> int:
        return max(self.ssh_rate_limit_window, 300)


def parse_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _normalize_set(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(value.lower() for value in values)


def load_env_file(env_file: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    if not env_file.exists():
        return parsed

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        parsed[key.strip()] = value
    return parsed


def _get_env_value(key: str, env_values: dict[str, str], default: str = "") -> str:
    if key in os.environ:
        return os.environ[key]
    return env_values.get(key, default)


def _resolve_env_file(env_file: str | None) -> Path:
    if env_file:
        return Path(env_file).expanduser().resolve()

    candidate = os.environ.get("SSHOOK_ENV_FILE")
    if candidate:
        return Path(candidate).expanduser().resolve()

    return DEFAULT_ENV_FILE.resolve()


def load_settings(env_file: str | None = None, *, require_webhook: bool = True) -> Settings:
    resolved_env_file = _resolve_env_file(env_file)
    env_values = load_env_file(resolved_env_file)

    discord_webhook_url = _get_env_value("DISCORD_WEBHOOK_URL", env_values, "").strip()
    if require_webhook and not discord_webhook_url:
        raise ConfigError(
            f"DISCORD_WEBHOOK_URL no está configurado. Archivo esperado: {resolved_env_file}"
        )

    hostname_alias = _get_env_value("HOSTNAME_ALIAS", env_values, "").strip() or socket.gethostname()
    ssh_log_mode = _get_env_value("SSH_LOG_MODE", env_values, "auto").strip().lower()
    if ssh_log_mode not in {"auto", "journald", "authlog", "secure", "file"}:
        raise ConfigError("SSH_LOG_MODE debe ser auto, journald, authlog, secure o file.")

    ssh_journal_units = parse_csv(_get_env_value("SSH_JOURNAL_UNIT", env_values, ""))
    ssh_log_file = _get_env_value("SSH_LOG_FILE", env_values, "").strip() or None

    try:
        ssh_poll_interval = float(_get_env_value("SSH_POLL_INTERVAL", env_values, "5"))
    except ValueError as exc:
        raise ConfigError("SSH_POLL_INTERVAL debe ser numérico.") from exc
    if ssh_poll_interval <= 0:
        raise ConfigError("SSH_POLL_INTERVAL debe ser mayor que cero.")

    try:
        ssh_rate_limit_window = int(_get_env_value("SSH_RATE_LIMIT_WINDOW", env_values, "60"))
        ssh_rate_limit_burst = int(_get_env_value("SSH_RATE_LIMIT_BURST", env_values, "10"))
    except ValueError as exc:
        raise ConfigError(
            "SSH_RATE_LIMIT_WINDOW y SSH_RATE_LIMIT_BURST deben ser enteros."
        ) from exc
    if ssh_rate_limit_window <= 0 or ssh_rate_limit_burst <= 0:
        raise ConfigError("Los valores de rate limit deben ser mayores que cero.")

    state_dir = Path(_get_env_value("STATE_DIR", env_values, "/var/lib/sshook")).expanduser()
    log_dir = Path(_get_env_value("LOG_DIR", env_values, "/var/log/sshook")).expanduser()
    log_level = _get_env_value("LOG_LEVEL", env_values, "INFO").strip().upper() or "INFO"

    return Settings(
        discord_webhook_url=discord_webhook_url,
        hostname_alias=hostname_alias,
        ssh_log_mode=ssh_log_mode,
        ssh_journal_units=ssh_journal_units,
        ssh_log_file=ssh_log_file,
        ssh_poll_interval=ssh_poll_interval,
        ssh_ignore_ips=_normalize_set(parse_csv(_get_env_value("SSH_IGNORE_IPS", env_values, ""))),
        ssh_ignore_users=_normalize_set(
            parse_csv(_get_env_value("SSH_IGNORE_USERS", env_values, ""))
        ),
        ssh_rate_limit_window=ssh_rate_limit_window,
        ssh_rate_limit_burst=ssh_rate_limit_burst,
        state_dir=state_dir,
        log_dir=log_dir,
        log_level=log_level,
        env_file=resolved_env_file,
    )
