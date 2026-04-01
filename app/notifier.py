from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib import error, request

from app.formatters import build_discord_payload

if TYPE_CHECKING:
    from app.ssh_watcher import SSHEvent


DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "SSHook/0.1 (+https://github.com/Marbin891/SSHook)",
}


class DiscordWebhookNotifier:
    def __init__(self, webhook_url: str, logger):
        self.webhook_url = webhook_url
        self.logger = logger

    def send_payload(self, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        req = request.Request(
            self.webhook_url,
            data=encoded,
            headers=DEFAULT_HEADERS,
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=10) as response:
                if response.status >= 400:
                    raise RuntimeError(f"Discord devolvió HTTP {response.status}")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Discord devolvió HTTP {exc.code}: {body}") from exc
        except error.URLError as exc:
            raise RuntimeError(f"No se pudo conectar al webhook de Discord: {exc}") from exc

    def send_event(self, event: "SSHEvent") -> None:
        self.send_payload(build_discord_payload(event))
