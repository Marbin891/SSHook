from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ssh_watcher import SSHEvent


EVENT_TITLES = {
    "login_success": "Inicio de sesión SSH exitoso",
    "login_failed": "Inicio de sesión SSH fallido",
    "logout": "Sesión SSH cerrada",
}

EVENT_COLORS = {
    "login_success": 0x2ECC71,
    "login_failed": 0xE74C3C,
    "logout": 0x95A5A6,
}

EVENT_SEVERITY = {
    "login_success": "info",
    "login_failed": "high",
    "logout": "medium",
}


def build_discord_payload(event: "SSHEvent") -> dict[str, object]:
    event_type = EVENT_TITLES.get(event.event_type, event.event_type)
    color = EVENT_COLORS.get(event.event_type, 0x3498DB)
    severity = EVENT_SEVERITY.get(event.event_type, event.severity)

    return {
        "username": "SSHook",
        "content": None,
        "embeds": [
            {
                "title": event_type,
                "color": color,
                "description": f"Alerta SSH detectada en `{event.hostname}`.",
                "fields": [
                    {"name": "Servidor", "value": event.hostname, "inline": True},
                    {"name": "Usuario", "value": event.username or "unknown", "inline": True},
                    {"name": "IP origen", "value": event.source_ip or "unknown", "inline": True},
                    {"name": "Hora", "value": event.timestamp.isoformat(), "inline": True},
                    {"name": "Severidad", "value": severity, "inline": True},
                    {"name": "Fuente", "value": event.source_name, "inline": True},
                ],
                "footer": {"text": "SSHook | SSH alerts via Discord webhook"},
            }
        ],
    }
