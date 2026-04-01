# SSHook

SSHook envía alertas de eventos SSH a Discord usando un webhook.

La idea es simple: configurar una URL de webhook, instalar el servicio y recibir avisos cuando hay accesos SSH exitosos, intentos fallidos o cierres de sesión cuando el sistema los registra.

## Qué hace

- detecta inicios de sesión SSH exitosos
- detecta intentos fallidos de autenticación
- detecta cierres de sesión cuando el log lo permite
- soporta `journald`, `/var/log/auth.log`, `/var/log/secure` y un archivo de entrada manual
- envía alertas a Discord con embeds claros
- permite ignorar IPs y usuarios
- aplica deduplicación y rate limiting básico
- guarda estado simple para no reprocesar eventos tras reinicios
- puede ejecutarse como servicio con `systemd` o en modo manual

## Requisitos

- Linux con `systemd`
- Python 3.10 o superior
- acceso de lectura a la fuente de logs SSH elegida
- salida de red hacia Discord

## Flujo rápido

```bash
git clone https://github.com/Marbin891/SSHook.git SSHook
cd SSHook
./scripts/example-env-setup.sh
nano .env
./scripts/test_webhook.sh
sudo ./scripts/install.sh
sudo systemctl enable --now sshook.service
sudo systemctl status sshook.service
```

## Crear el webhook en Discord

1. Abre el canal donde quieres recibir las alertas.
2. Entra en `Editar canal`.
3. Abre `Integraciones`.
4. Entra en `Webhooks`.
5. Crea un webhook nuevo.
6. Copia la URL.
7. Pégala en `DISCORD_WEBHOOK_URL` dentro de `.env`.

## Configuración

Copia primero el archivo de ejemplo:

```bash
./scripts/example-env-setup.sh
```

Después edita `.env` y ajusta lo necesario.

Variables principales:

- `DISCORD_WEBHOOK_URL`: URL del webhook de Discord.
- `HOSTNAME_ALIAS`: nombre que aparecerá en las alertas. Si se deja vacío, se usa el hostname del sistema.
- `SSH_LOG_MODE`: `auto`, `journald`, `authlog`, `secure` o `file`.
- `SSH_JOURNAL_UNIT`: units opcionales para filtrar `journalctl`, separadas por comas.
- `SSH_LOG_FILE`: ruta de archivo si usas `SSH_LOG_MODE=file`.
- `SSH_POLL_INTERVAL`: intervalo de lectura en segundos.
- `SSH_IGNORE_IPS`: lista de IPs a ignorar, separadas por comas.
- `SSH_IGNORE_USERS`: lista de usuarios a ignorar, separados por comas.
- `SSH_RATE_LIMIT_WINDOW`: ventana del rate limit en segundos.
- `SSH_RATE_LIMIT_BURST`: número máximo de alertas por combinación evento/usuario/IP dentro de esa ventana.
- `STATE_DIR`: directorio para estado persistente.
- `LOG_DIR`: directorio para logs de la aplicación.
- `LOG_LEVEL`: `DEBUG`, `INFO`, `WARNING` o `ERROR`.

El archivo de ejemplo está en [config/.env.example](/config/projects/ssh-dscrd/config/.env.example).

## Instalación

Con el webhook ya configurado, instala SSHook con:

```bash
sudo ./scripts/install.sh
```

El instalador:

- copia el proyecto a `/opt/sshook`
- instala la unidad en `/etc/systemd/system/sshook.service`
- crea los directorios definidos en `STATE_DIR` y `LOG_DIR`

Después habilita y arranca el servicio:

```bash
sudo systemctl enable --now sshook.service
```

Comprueba el estado:

```bash
sudo systemctl status sshook.service
```

## Probar el webhook

Antes o después de instalar, puedes verificar que Discord acepta el webhook:

```bash
./scripts/test_webhook.sh
```

Si quieres usar otro archivo de entorno:

```bash
./scripts/test_webhook.sh /ruta/a/.env
```

## Modo manual

Validar la configuración:

```bash
python3 app/main.py --validate-config --env-file .env
```

Procesar un archivo de muestra sin enviar nada a Discord:

```bash
python3 app/main.py --env-file .env --input-file samples/auth.log.sample --no-notify --debug
```

Procesar ese mismo archivo y enviar alertas reales:

```bash
python3 app/main.py --env-file .env --input-file samples/auth.log.sample
```

Leer una sola vez la fuente real configurada:

```bash
python3 app/main.py --env-file .env --once --debug --no-notify
```

## Logs y diagnóstico

Ver estado del servicio:

```bash
sudo systemctl status sshook.service
```

Seguir logs del servicio:

```bash
sudo journalctl -u sshook.service -f
```

Ver el log propio de la aplicación:

```bash
sudo tail -f /var/log/sshook/sshook.log
```

Healthcheck básico:

```bash
./scripts/healthcheck.sh
```

## Troubleshooting

### No aparecen eventos

- prueba `SSH_LOG_MODE=authlog` o `SSH_LOG_MODE=secure` si `auto` no detecta bien tu sistema
- si usas `journald`, deja `SSH_JOURNAL_UNIT` vacío primero
- ejecuta `python3 app/main.py --env-file .env --once --debug --no-notify` para ver qué fuente se está usando

### El servicio corre pero no llegan alertas

- ejecuta `./scripts/test_webhook.sh`
- revisa conectividad saliente a `discord.com`
- consulta `sudo journalctl -u sshook.service -f`

### Problemas de permisos al leer logs

- en muchos sistemas lo más simple es ejecutar el servicio como `root`
- si cambias el usuario del servicio, asegúrate de que pueda leer `journald` o los archivos de autenticación del sistema

### Rotación de logs

SSHook guarda inode y offset. Si el archivo rota o se trunca, reinicia la lectura desde el inicio del archivo nuevo.

## Seguridad

- el webhook de Discord debe tratarse como secreto
- mantén permisos restrictivos sobre el archivo de configuración
- usa `SSH_IGNORE_IPS` y `SSH_IGNORE_USERS` para reducir ruido innecesario
- el rate limiting evita tormentas de alertas repetidas, pero no sustituye medidas de seguridad SSH

## Estructura del proyecto

```text
SSHook/
├── app/
├── config/
├── samples/
├── scripts/
├── services/
├── .gitignore
├── LICENSE
├── pyproject.toml
├── README.md
└── requirements.txt
```

## Desinstalación

Desinstalación básica:

```bash
sudo ./scripts/uninstall.sh
```

Desinstalación eliminando también estado y logs persistentes:

```bash
sudo ./scripts/uninstall.sh --purge-state
```

## Licencia

MIT.
