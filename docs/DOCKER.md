# Run the API and React dashboard with Docker

The multi-stage image builds the React/TypeScript dashboard and serves it from
FastAPI. It runs one API worker as a non-root user. It contains no trained models
or capture tools and does not start a sensor or firewall helper.

## Existing PostgreSQL installation on Linux

Requirements: Docker Engine, Docker Compose, a running PostgreSQL server and the
existing private `backend/.env`. Preserve that file and its database URL, JWT key
and sensor credentials. The build excludes credentials, runtime files, models,
datasets and local dependencies. Compose mounts the configuration read-only at
runtime; it does not copy it into the image.

```bash
cd "/home/abdulsamad/Projects/SecureNet AI"
docker compose up -d --build --wait
```

Open <http://127.0.0.1:8010> and use your existing administrator account. The
container serves both the dashboard and API; a separate Vite process is not needed.

Compose uses [host networking](https://docs.docker.com/engine/network/drivers/host/)
so `localhost` in the current PostgreSQL URL reaches the host database. The API
binds only to `127.0.0.1:8010`; no `ports` mapping is needed. Stop an existing
SecureNet API on that port before starting Docker, or select another port:

```bash
SECURENET_PORT=8011 docker compose up -d --build --wait
```

The default container UID/GID is `1000:1000`, matching this checkout's owner. If
your private `0600` environment file has a different owner, set
`SECURENET_UID=$(id -u) SECURENET_GID=$(id -g)` when running Compose. Keep the file
private. `SECURENET_ENV_FILE` selects another configuration file without editing
the original. These overrides should be reused for subsequent Compose commands.

```bash
docker compose ps
docker compose logs --tail=100 server
docker compose down
```

Stopping/removing the container leaves the existing host PostgreSQL database in
place. Startup uses the application's normal schema validation; it does not run
the migration CLI or create an administrator. For an older schema, back up the
database and apply the explicit migration in [BACKEND.md](BACKEND.md) first.

## Build or run the image directly

```bash
docker build -t securenet-ai:local .
docker run --rm --network host \
  -e UVICORN_HOST=127.0.0.1 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/backend/.env,dst=/app/backend/.env,readonly" \
  -e UVICORN_HOST=127.0.0.1 \
  securenet-ai:local
```

The image defaults to `0.0.0.0:8010` for ordinary Docker bridge networks. When
using bridge networking, publish `127.0.0.1:8010:8010` and supply a database URL
reachable from that container; container `localhost` is then the container itself.
The supplied Compose file targets this Linux installation and existing host
PostgreSQL. It does not provision another database or switch to SQLite. Docker
Desktop requires host networking to be enabled, or a separate bridge/database
configuration.

For a fresh PostgreSQL installation, generate private configuration with the
existing backend management CLI, migrate the selected database and create the
initial administrator as described in [BACKEND.md](BACKEND.md). Once the image is
built, equivalent management commands can be run with `docker compose run --rm
server python -m backend.manage ...`; create-admin prompts interactively.
