from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.config import DEFAULT_AUTH_LOG, DEFAULT_SECURE_LOG, Settings
from app.state_store import JSONStateStore


SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<hostname>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.+)$"
)
ISO_PREFIX_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d\d-\d\d[T ][^ ]+)\s+"
    r"(?P<hostname>\S+)\s+(?P<process>[^:]+):\s+(?P<message>.+)$"
)
ACCEPTED_RE = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
SESSION_CLOSED_RE = re.compile(
    r"session closed for user (?P<username>\S+)",
    re.IGNORECASE,
)
DISCONNECTED_RE = re.compile(
    r"Disconnected from user (?P<username>\S+)\s+(?P<ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
RECEIVED_DISCONNECT_RE = re.compile(
    r"Received disconnect from (?P<ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)
UNKNOWN_VALUE = "unknown"
SESSION_CACHE_TTL = 43200
LOGOUT_DEDUPE_WINDOW_SECONDS = 5


@dataclass(slots=True)
class SSHEvent:
    event_type: str
    severity: str
    timestamp: datetime
    hostname: str
    username: str
    source_ip: str
    raw_message: str
    source_name: str

    def fingerprint(self) -> str:
        base = "|".join(
            [
                self.event_type,
                self.hostname,
                self.username,
                self.source_ip,
                self.raw_message,
                self.source_name,
            ]
        )
        return hashlib.sha1(base.encode("utf-8")).hexdigest()


class BasicRateLimiter:
    def __init__(self, window_seconds: int, burst: int):
        self.window_seconds = window_seconds
        self.burst = burst
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        queue = self.events[key]

        while queue and current - queue[0] > self.window_seconds:
            queue.popleft()

        if len(queue) >= self.burst:
            return False

        queue.append(current)
        return True


class SessionTracker:
    def __init__(self, ttl_seconds: int = SESSION_CACHE_TTL):
        self.ttl_seconds = ttl_seconds
        self.by_user: dict[str, tuple[str, float]] = {}
        self.by_ip: dict[str, tuple[str, float]] = {}

    def prune(self, now: float) -> None:
        expired_users = [user for user, (_, ts) in self.by_user.items() if now - ts > self.ttl_seconds]
        for user in expired_users:
            self.by_user.pop(user, None)

        expired_ips = [ip for ip, (_, ts) in self.by_ip.items() if now - ts > self.ttl_seconds]
        for ip in expired_ips:
            self.by_ip.pop(ip, None)

    def remember_login(self, username: str, ip: str, now: float) -> None:
        if username and username != UNKNOWN_VALUE and ip and ip != UNKNOWN_VALUE:
            self.by_user[username.lower()] = (ip, now)
            self.by_ip[ip] = (username, now)
        self.prune(now)

    def enrich_logout(self, event: SSHEvent, now: float) -> SSHEvent:
        self.prune(now)

        username = event.username
        source_ip = event.source_ip

        if username != UNKNOWN_VALUE and source_ip == UNKNOWN_VALUE:
            remembered = self.by_user.get(username.lower())
            if remembered is not None:
                source_ip = remembered[0]

        if source_ip != UNKNOWN_VALUE and username == UNKNOWN_VALUE:
            remembered = self.by_ip.get(source_ip)
            if remembered is not None:
                username = remembered[0]

        if username == event.username and source_ip == event.source_ip:
            return event

        return SSHEvent(
            event_type=event.event_type,
            severity=event.severity,
            timestamp=event.timestamp,
            hostname=event.hostname,
            username=username,
            source_ip=source_ip,
            raw_message=event.raw_message,
            source_name=event.source_name,
        )

    def forget_logout(self, event: SSHEvent) -> None:
        if event.username != UNKNOWN_VALUE:
            self.by_user.pop(event.username.lower(), None)
        if event.source_ip != UNKNOWN_VALUE:
            self.by_ip.pop(event.source_ip, None)


class LogSource:
    name: str

    def read(self, state: dict[str, object]) -> tuple[list[str], dict[str, object]]:
        raise NotImplementedError

    def describe(self) -> str:
        return self.name


class FileLogSource(LogSource):
    def __init__(self, path: Path, *, start_at_end: bool):
        self.path = path
        self.name = f"file:{self.path}"
        self.start_at_end = start_at_end

    def describe(self) -> str:
        return str(self.path)

    def read(self, state: dict[str, object]) -> tuple[list[str], dict[str, object]]:
        if not self.path.exists():
            return [], state

        stat_result = self.path.stat()
        inode = int(stat_result.st_ino)
        file_size = int(stat_result.st_size)

        offset = int(state.get("offset", 0))
        previous_inode = int(state.get("inode", 0))

        if not state:
            if self.start_at_end:
                return [], {"inode": inode, "offset": file_size}
            offset = 0

        if previous_inode and previous_inode != inode:
            offset = 0
        elif offset > file_size:
            offset = 0

        with self.path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            lines = handle.read().splitlines()
            new_offset = handle.tell()

        return lines, {"inode": inode, "offset": new_offset}


class JournalctlSource(LogSource):
    def __init__(self, units: tuple[str, ...], *, start_at_end: bool):
        self.units = units
        self.start_at_end = start_at_end
        self.name = "journald"

    def describe(self) -> str:
        if self.units:
            return f"journald units={','.join(self.units)}"
        return "journald"

    def read(self, state: dict[str, object]) -> tuple[list[str], dict[str, object]]:
        now = time.time()
        since_epoch = float(state.get("since_epoch", now if self.start_at_end else 0.0))

        command = [
            "journalctl",
            "--no-pager",
            "--output=short-iso",
            f"--since=@{int(since_epoch)}",
        ]
        for unit in self.units:
            command.extend(["-u", unit])

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip() or "journalctl devolvió error"
            raise RuntimeError(stderr)

        lines = [
            line
            for line in result.stdout.splitlines()
            if "sshd[" in line or " sshd:" in line or "sshd-session" in line
        ]
        return lines, {"since_epoch": now}



def can_use_journalctl(logger: logging.Logger, units: tuple[str, ...]) -> bool:
    command = ["journalctl", "--no-pager", "--output=short-iso", "-n", "1"]
    for unit in units:
        command.extend(["-u", unit])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        logger.debug("journald no disponible: %s", exc)
        return False

    if result.returncode != 0:
        logger.debug("journalctl no usable: %s", result.stderr.strip())
        return False
    return True



def select_log_source(
    settings: Settings,
    logger: logging.Logger,
    *,
    input_file: str | None = None,
    oneshot: bool = False,
) -> LogSource:
    if input_file:
        return FileLogSource(Path(input_file).expanduser().resolve(), start_at_end=False)

    if settings.ssh_log_mode == "journald":
        return JournalctlSource(settings.ssh_journal_units, start_at_end=not oneshot)
    if settings.ssh_log_mode == "authlog":
        return FileLogSource(DEFAULT_AUTH_LOG, start_at_end=not oneshot)
    if settings.ssh_log_mode == "secure":
        return FileLogSource(DEFAULT_SECURE_LOG, start_at_end=not oneshot)
    if settings.ssh_log_mode == "file":
        if not settings.ssh_log_file:
            raise RuntimeError("SSH_LOG_FILE es obligatorio cuando SSH_LOG_MODE=file.")
        return FileLogSource(Path(settings.ssh_log_file).expanduser(), start_at_end=not oneshot)

    if can_use_journalctl(logger, settings.ssh_journal_units):
        return JournalctlSource(settings.ssh_journal_units, start_at_end=not oneshot)
    if settings.ssh_log_file and Path(settings.ssh_log_file).expanduser().exists():
        return FileLogSource(Path(settings.ssh_log_file).expanduser(), start_at_end=not oneshot)
    if DEFAULT_AUTH_LOG.exists():
        return FileLogSource(DEFAULT_AUTH_LOG, start_at_end=not oneshot)
    if DEFAULT_SECURE_LOG.exists():
        return FileLogSource(DEFAULT_SECURE_LOG, start_at_end=not oneshot)

    raise RuntimeError(
        "No se encontró una fuente SSH usable. Ajusta SSH_LOG_MODE o SSH_LOG_FILE."
    )



def parse_timestamp(raw_timestamp: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(raw_timestamp.replace(" ", "T"))
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=UTC)
        return timestamp
    except ValueError:
        current_year = datetime.now(UTC).year
        parsed = datetime.strptime(f"{current_year} {raw_timestamp}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=UTC)



def parse_ssh_event(line: str, settings: Settings, source_name: str) -> SSHEvent | None:
    raw_line = line.strip()
    if not raw_line:
        return None

    timestamp = datetime.now(UTC)
    hostname = settings.hostname_alias
    message = raw_line
    process_name = ""

    prefix_match = ISO_PREFIX_RE.match(raw_line) or SYSLOG_PREFIX_RE.match(raw_line)
    if prefix_match:
        timestamp = parse_timestamp(prefix_match.group("timestamp"))
        hostname = settings.hostname_alias or prefix_match.group("hostname")
        message = prefix_match.group("message")
        process_name = prefix_match.group("process").lower()

    if process_name and "sshd" not in process_name and "sshd-session" not in process_name:
        return None

    accepted = ACCEPTED_RE.search(message)
    if accepted:
        return SSHEvent(
            event_type="login_success",
            severity="info",
            timestamp=timestamp,
            hostname=hostname,
            username=accepted.group("username"),
            source_ip=accepted.group("ip"),
            raw_message=raw_line,
            source_name=source_name,
        )

    failed = FAILED_RE.search(message)
    if failed:
        return SSHEvent(
            event_type="login_failed",
            severity="high",
            timestamp=timestamp,
            hostname=hostname,
            username=failed.group("username"),
            source_ip=failed.group("ip"),
            raw_message=raw_line,
            source_name=source_name,
        )

    disconnected = DISCONNECTED_RE.search(message)
    if disconnected:
        return SSHEvent(
            event_type="logout",
            severity="medium",
            timestamp=timestamp,
            hostname=hostname,
            username=disconnected.group("username"),
            source_ip=disconnected.group("ip"),
            raw_message=raw_line,
            source_name=source_name,
        )

    session_closed = SESSION_CLOSED_RE.search(message)
    if session_closed:
        return SSHEvent(
            event_type="logout",
            severity="medium",
            timestamp=timestamp,
            hostname=hostname,
            username=session_closed.group("username"),
            source_ip=UNKNOWN_VALUE,
            raw_message=raw_line,
            source_name=source_name,
        )

    received_disconnect = RECEIVED_DISCONNECT_RE.search(message)
    if received_disconnect:
        return SSHEvent(
            event_type="logout",
            severity="medium",
            timestamp=timestamp,
            hostname=hostname,
            username=UNKNOWN_VALUE,
            source_ip=received_disconnect.group("ip"),
            raw_message=raw_line,
            source_name=source_name,
        )

    return None


class SSHWatcher:
    def __init__(
        self,
        settings: Settings,
        logger: logging.Logger,
        state_store: JSONStateStore,
        notifier: object | None,
        *,
        input_file: str | None = None,
        oneshot: bool = False,
        no_notify: bool = False,
    ):
        self.settings = settings
        self.logger = logger
        self.state_store = state_store
        self.notifier = notifier
        self.input_file = input_file
        self.oneshot = oneshot
        self.no_notify = no_notify
        self.source = select_log_source(settings, logger, input_file=input_file, oneshot=oneshot)
        self.rate_limiter = BasicRateLimiter(
            settings.ssh_rate_limit_window,
            settings.ssh_rate_limit_burst,
        )
        self.session_tracker = SessionTracker()

    def should_ignore(self, event: SSHEvent) -> bool:
        if event.source_ip.lower() in self.settings.ssh_ignore_ips:
            return True
        if event.username.lower() in self.settings.ssh_ignore_users:
            return True
        return False

    def emit(self, event: SSHEvent) -> None:
        summary = (
            f"evento={event.event_type} user={event.username} "
            f"ip={event.source_ip} host={event.hostname}"
        )

        if self.no_notify or self.notifier is None:
            self.logger.info("Detectado %s", summary)
            return

        self.notifier.send_event(event)
        self.logger.info("Notificación enviada %s", summary)

    def normalized_fingerprint(self, event: SSHEvent) -> str:
        if event.event_type != "logout":
            return event.fingerprint()

        timestamp_bucket = int(event.timestamp.timestamp() // LOGOUT_DEDUPE_WINDOW_SECONDS)
        base = "|".join(
            [
                event.event_type,
                event.hostname,
                event.username,
                event.source_ip,
                str(timestamp_bucket),
            ]
        )
        return hashlib.sha1(base.encode("utf-8")).hexdigest()

    def prepare_event(self, event: SSHEvent, now: float) -> SSHEvent:
        if event.event_type == "login_success":
            self.session_tracker.remember_login(event.username, event.source_ip, now)
            return event

        if event.event_type == "logout":
            enriched = self.session_tracker.enrich_logout(event, now)
            return enriched

        return event

    def finalize_event(self, event: SSHEvent) -> None:
        # No eliminamos la correlación al primer logout porque sshd/pam puede
        # emitir más de una línea de cierre para la misma sesión en el mismo
        # segundo. Dejamos que expire por TTL y que la deduplicación suprima
        # los duplicados.
        return None

    def process_lines(self, lines: list[str]) -> int:
        processed = 0
        for line in lines:
            event = parse_ssh_event(line, self.settings, self.source.describe())
            if event is None:
                continue

            now = time.time()
            event = self.prepare_event(event, now)

            if self.should_ignore(event):
                self.logger.debug(
                    "Evento ignorado por whitelist: user=%s ip=%s",
                    event.username,
                    event.source_ip,
                )
                continue

            fingerprint = self.normalized_fingerprint(event)
            if self.state_store.seen_recently(fingerprint, self.settings.dedupe_ttl, now):
                self.logger.debug("Evento duplicado suprimido: %s", fingerprint)
                continue

            rate_key = f"{event.event_type}:{event.username}:{event.source_ip}"
            if not self.rate_limiter.allow(rate_key, now):
                self.logger.warning("Evento suprimido por rate limit: %s", rate_key)
                continue

            self.emit(event)
            self.state_store.mark_seen(fingerprint, now)
            self.finalize_event(event)
            processed += 1

        if processed:
            self.state_store.save()
        return processed

    def poll_once(self) -> int:
        source_state = self.state_store.get_source_state(self.source.name)
        lines, new_source_state = self.source.read(source_state)
        self.state_store.update_source_state(self.source.name, new_source_state)
        self.state_store.save()

        if not lines:
            return 0

        self.logger.debug(
            "Leídas %s líneas desde %s",
            len(lines),
            self.source.describe(),
        )
        return self.process_lines(lines)

    def run(self) -> int:
        self.logger.info("Fuente SSH seleccionada: %s", self.source.describe())

        if self.oneshot:
            return self.poll_once()

        while True:
            try:
                self.poll_once()
            except Exception as exc:
                self.logger.exception("Error durante el ciclo de monitoreo: %s", exc)
            time.sleep(self.settings.ssh_poll_interval)
