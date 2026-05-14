from __future__ import annotations

import os
import logging
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.config import ConfigError, load_env_file, load_settings
from app.ssh_watcher import SSHEvent, SSHWatcher
from app.state_store import JSONStateStore


ENV_KEYS = (
    "DISCORD_WEBHOOK_URL",
    "HOSTNAME_ALIAS",
    "SSH_LOG_MODE",
    "SSH_JOURNAL_UNIT",
    "SSH_LOG_FILE",
    "SSH_POLL_INTERVAL",
    "SSH_IGNORE_IPS",
    "SSH_IGNORE_USERS",
    "SSH_RATE_LIMIT_WINDOW",
    "SSH_RATE_LIMIT_BURST",
    "STATE_DIR",
    "LOG_DIR",
    "LOG_LEVEL",
    "SSHOOK_ENV_FILE",
)


@contextmanager
def clean_env():
    saved = {key: os.environ[key] for key in ENV_KEYS if key in os.environ}
    for key in ENV_KEYS:
        os.environ.pop(key, None)
    try:
        yield
    finally:
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        os.environ.update(saved)


class SecurityRegressionTests(unittest.TestCase):
    def write_env(self, content: str) -> Path:
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        with handle:
            handle.write(content)
        return Path(handle.name)

    def make_watcher(self) -> tuple[SSHWatcher, "_FakeNotifier"]:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        base_path = Path(temp_dir.name)
        input_file = base_path / "auth.log"
        input_file.write_text("", encoding="utf-8")
        env_file = self.write_env(
            "\n".join(
                [
                    "HOSTNAME_ALIAS=casa-jrz-01",
                    f"STATE_DIR={base_path / 'state'}",
                    f"LOG_DIR={base_path / 'log'}",
                    "SSH_RATE_LIMIT_WINDOW=60",
                    "SSH_RATE_LIMIT_BURST=10",
                ]
            )
        )

        with clean_env():
            settings = load_settings(str(env_file), require_webhook=False)

        state_store = JSONStateStore(settings.state_dir)
        state_store.load()
        notifier = _FakeNotifier()
        watcher = SSHWatcher(
            settings,
            logging.getLogger("sshook.tests"),
            state_store,
            notifier,
            input_file=str(input_file),
        )
        return watcher, notifier

    def test_discord_webhook_must_use_https(self) -> None:
        env_file = self.write_env(
            "DISCORD_WEBHOOK_URL=http://discord.com/api/webhooks/webhook-id/webhook-token\n"
        )

        with clean_env(), self.assertRaisesRegex(ConfigError, "HTTPS"):
            load_settings(str(env_file))

    def test_discord_webhook_must_target_discord(self) -> None:
        env_file = self.write_env(
            "DISCORD_WEBHOOK_URL=https://example.com/api/webhooks/webhook-id/webhook-token\n"
        )

        with clean_env(), self.assertRaisesRegex(ConfigError, "discord.com"):
            load_settings(str(env_file))

    def test_discord_webhook_accepts_expected_shape(self) -> None:
        env_file = self.write_env(
            "DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/webhook-id/webhook-token\n"
        )

        with clean_env():
            settings = load_settings(str(env_file))

        self.assertEqual(
            settings.discord_webhook_url,
            "https://discord.com/api/webhooks/webhook-id/webhook-token",
        )

    def test_env_file_is_parsed_as_data(self) -> None:
        env_file = self.write_env("STATE_DIR=$(touch /tmp/sshook-env-executed)\n")

        parsed = load_env_file(env_file)

        self.assertEqual(parsed["STATE_DIR"], "$(touch /tmp/sshook-env-executed)")

    def test_event_fingerprint_uses_sha256_length(self) -> None:
        event = SSHEvent(
            event_type="login_failed",
            severity="high",
            timestamp=datetime(2026, 5, 13, tzinfo=UTC),
            hostname="prod-a",
            username="admin",
            source_ip="198.51.100.42",
            raw_message="Failed password for invalid user admin from 198.51.100.42",
            source_name="sample",
        )

        self.assertEqual(len(event.fingerprint()), 64)

    def test_logout_lines_from_one_session_are_coalesced(self) -> None:
        watcher, notifier = self.make_watcher()

        processed = watcher.process_lines(
            [
                (
                    "2026-05-14T10:32:47 casa-jrz-01 sshd-session[123]: "
                    "Received disconnect from 192.168.60.2 port 55320:11: disconnected by user"
                ),
                (
                    "2026-05-14T10:32:47 casa-jrz-01 sshd-session[123]: "
                    "Disconnected from user pelofeo 192.168.60.2 port 55320"
                ),
                (
                    "2026-05-14T10:32:47 casa-jrz-01 sshd-session[123]: "
                    "pam_unix(sshd:session): session closed for user pelofeo"
                ),
            ]
        )

        self.assertEqual(processed, 1)
        self.assertEqual(len(notifier.events), 1)
        self.assertEqual(notifier.events[0].username, "pelofeo")
        self.assertEqual(notifier.events[0].source_ip, "192.168.60.2")

    def test_logout_partial_line_is_suppressed_after_full_logout(self) -> None:
        watcher, notifier = self.make_watcher()

        first_processed = watcher.process_lines(
            [
                (
                    "2026-05-14T10:32:47 casa-jrz-01 sshd: "
                    "Disconnected from user pelofeo 192.168.60.2 port 55320"
                )
            ]
        )
        second_processed = watcher.process_lines(
            [
                (
                    "2026-05-14T10:32:47 casa-jrz-01 sshd: "
                    "pam_unix(sshd:session): session closed for user pelofeo"
                )
            ]
        )

        self.assertEqual(first_processed, 1)
        self.assertEqual(second_processed, 0)
        self.assertEqual(len(notifier.events), 1)

    def test_session_closed_reuses_login_port_for_dedupe(self) -> None:
        watcher, notifier = self.make_watcher()

        login_processed = watcher.process_lines(
            [
                (
                    "2026-05-14T10:56:29 casa-jrz-01 sshd[456]: "
                    "Accepted publickey for pelofeo from 192.168.60.2 port 55320 ssh2"
                )
            ]
        )
        logout_processed = watcher.process_lines(
            [
                (
                    "2026-05-14T10:56:44 casa-jrz-01 sshd[456]: "
                    "Disconnected from user pelofeo 192.168.60.2 port 55320"
                ),
                (
                    "2026-05-14T10:56:44 casa-jrz-01 sshd[456]: "
                    "pam_unix(sshd:session): session closed for user pelofeo"
                ),
            ]
        )

        self.assertEqual(login_processed, 1)
        self.assertEqual(logout_processed, 1)
        self.assertEqual(len(notifier.events), 2)
        self.assertEqual(notifier.events[1].event_type, "logout")
        self.assertEqual(notifier.events[1].username, "pelofeo")
        self.assertEqual(notifier.events[1].source_ip, "192.168.60.2")
        self.assertEqual(notifier.events[1].source_port, "55320")


class _FakeNotifier:
    def __init__(self) -> None:
        self.events: list[SSHEvent] = []

    def send_event(self, event: SSHEvent) -> None:
        self.events.append(event)


if __name__ == "__main__":
    unittest.main()
