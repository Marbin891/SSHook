from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class JSONStateStore:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_file = self.state_dir / "state.json"
        self.state: dict[str, Any] = {
            "sources": {},
            "dedupe": {},
        }

    def load(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        if not self.state_file.exists():
            return

        try:
            loaded = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        if isinstance(loaded, dict):
            self.state.update(loaded)
            self.state.setdefault("sources", {})
            self.state.setdefault("dedupe", {})

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.state, indent=2, sort_keys=True)
        temp_file = self.state_file.with_suffix(".tmp")
        temp_file.write_text(payload, encoding="utf-8")
        temp_file.replace(self.state_file)

    def get_source_state(self, source_name: str) -> dict[str, Any]:
        return dict(self.state["sources"].get(source_name, {}))

    def update_source_state(self, source_name: str, data: dict[str, Any]) -> None:
        self.state["sources"][source_name] = data

    def prune_dedupe(self, ttl_seconds: int, now: float | None = None) -> None:
        current = now if now is not None else time.time()
        dedupe = self.state.setdefault("dedupe", {})
        expired = [key for key, ts in dedupe.items() if current - float(ts) > ttl_seconds]
        for key in expired:
            dedupe.pop(key, None)

    def seen_recently(self, fingerprint: str, ttl_seconds: int, now: float | None = None) -> bool:
        current = now if now is not None else time.time()
        self.prune_dedupe(ttl_seconds, current)
        last_seen = self.state.setdefault("dedupe", {}).get(fingerprint)
        return last_seen is not None and current - float(last_seen) <= ttl_seconds

    def mark_seen(self, fingerprint: str, now: float | None = None) -> None:
        current = now if now is not None else time.time()
        self.state.setdefault("dedupe", {})[fingerprint] = current
