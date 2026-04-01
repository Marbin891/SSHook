from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import ConfigError, load_settings
from app.logger import configure_logging
from app.notifier import DiscordWebhookNotifier
from app.state_store import JSONStateStore
from app.ssh_watcher import SSHWatcher, select_log_source



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SSHook - alertas SSH por Discord webhook")
    parser.add_argument(
        "--env-file",
        default=None,
        help="Ruta al archivo .env. Por defecto usa ./.env o SSHOOK_ENV_FILE.",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Ejecuta en modo daemon. Es el comportamiento normal cuando no usas --once.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Lee una vez la fuente configurada y termina.",
    )
    parser.add_argument(
        "--input-file",
        default=None,
        help="Procesa un archivo de logs local en modo de prueba.",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="No envía al webhook. Solo detecta y escribe eventos al log.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Fuerza nivel DEBUG para troubleshooting.",
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Valida la configuración y termina.",
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="Valida configuración y accesibilidad básica de la fuente SSH sin enviar alertas.",
    )
    return parser



def healthcheck(args: argparse.Namespace) -> int:
    try:
        settings = load_settings(args.env_file, require_webhook=False)
        logger = configure_logging("DEBUG" if args.debug else settings.log_level, settings.log_dir)
        source = select_log_source(
            settings,
            logger,
            input_file=args.input_file,
            oneshot=True,
        )
    except (ConfigError, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 1

    report = {
        "ok": True,
        "env_file": str(settings.env_file),
        "source": source.describe(),
        "log_mode": settings.ssh_log_mode,
        "state_dir": str(settings.state_dir),
        "log_dir": str(settings.log_dir),
        "webhook_configured": bool(settings.discord_webhook_url),
        "hostname_alias": settings.hostname_alias,
    }
    print(json.dumps(report, indent=2))
    return 0



def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.healthcheck:
        return healthcheck(args)

    try:
        settings = load_settings(args.env_file, require_webhook=not args.no_notify)
    except ConfigError as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 1

    logger = configure_logging("DEBUG" if args.debug else settings.log_level, settings.log_dir)

    if args.validate_config:
        logger.info("Configuración válida usando %s", settings.env_file)
        return 0

    state_store = JSONStateStore(settings.state_dir)
    state_store.load()

    notifier = None
    if not args.no_notify:
        notifier = DiscordWebhookNotifier(settings.discord_webhook_url, logger)

    watcher = SSHWatcher(
        settings=settings,
        logger=logger,
        state_store=state_store,
        notifier=notifier,
        input_file=args.input_file,
        oneshot=args.once or bool(args.input_file),
        no_notify=args.no_notify,
    )

    try:
        watcher.run()
    except KeyboardInterrupt:
        logger.info("Interrupción recibida. SSHook se detiene.")
        return 0
    except Exception as exc:
        logger.exception("Error fatal en SSHook: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
