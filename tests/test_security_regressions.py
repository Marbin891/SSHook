from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from app.config import ConfigError, load_env_file, load_settings
from app.ssh_watcher import SSHEvent


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


if __name__ == "__main__":
    unittest.main()
