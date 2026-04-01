from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ssh_watcher import SSHEvent


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


def format_event_message(event: "SSHEvent") -> str:
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    username = event.username or "unknown"
    source_ip = event.source_ip or "unknown"

    if event.event_type == "login_success":
        return (
            f"🔓 Usuario {username} inició sesión por SSH en {event.hostname} "
            f"desde {source_ip} a las {timestamp}"
        )
    if event.event_type == "login_failed":
        return (
            f"🚫 Falló un intento de inicio de sesión SSH para el usuario {username} "
            f"en {event.hostname} desde {source_ip} a las {timestamp}"
        )
    return (
        f"🔒 Usuario {username} cerró su sesión SSH en {event.hostname} "
        f"desde {source_ip} a las {timestamp}"
    )



def build_discord_payload(event: "SSHEvent") -> dict[str, object]:
    color = EVENT_COLORS.get(event.event_type, 0x3498DB)
    severity = EVENT_SEVERITY.get(event.event_type, event.severity)
    message = format_event_message(event)

    return {
        "username": "SSHook",
        "content": None,
        "embeds": [
            {
                "title": "Alerta SSH",
                "color": color,
                "description": message,
                "fields": [
                    {"name": "Servidor", "value": event.hostname, "inline": True},
                    {"name": "Hora", "value": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "inline": True},
                    {"name": "Severidad", "value": severity, "inline": True},
                ],
                "footer": {"text": "SSHook | SSH alerts via Discord webhook"},
            }
        ],
    }
