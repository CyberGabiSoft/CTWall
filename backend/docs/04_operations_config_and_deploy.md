# Operations, Configuration, and Deployment

## 1. Configuration files

Primary runtime files:

- `backend/config.yaml` (local/default runtime config, canonical full template)

Config path resolution:

- env `CTWALL_CONFIG_PATH`,
- fallback `config.yaml` in current working directory.

## 2. Required environment variables

At minimum:

- no mandatory runtime env variables when config file is complete.

## 3. Common optional overrides

General:

- `PORT`
- `STORAGE_PATH`
- `LOG_LEVEL`
- `JWT_ISSUER`

Database pool tuning:

- `DB_MAX_OPEN_CONNS` (default `20`)
- `DB_MAX_IDLE_CONNS` (default `10`, clamped to max open)
- `DB_CONN_MAX_LIFETIME` (default `30m`)
- `DB_CONN_MAX_IDLE_TIME` (default `10m`)

Alertmanager integration:

- `ALERTMANAGER_ENABLED`
- `ALERTMANAGER_URL`
- additional tuning envs (poll/retry/group intervals, worker counts).

Runtime config/bootstrap:

- `CTWALL_CONFIG_PATH` - runtime config file path.
- `CTWALL_SECRETS_PATH` - runtime secrets file path (`jwt_secret_key`, `app_encryption_passphrase`, `app_encryption_salt`, Alertmanager auth).

## 4. Runtime subsystems

Configured in YAML:

1. `server` - listen port and timeouts.
2. `storage` - blob storage base path.
3. `logging` - runtime log level.
4. `database` - ping timeout and pool defaults.
5. `auth` - issuer/TTLs/cookie policy.
6. `malware.osv` - OSV source settings and sync intervals.
7. `workers` - ingest and analysis worker counts + queue safety caps.

## 5. Local startup path

Recommended script:

- `manual-test-scripts/run_server.sh`

Script behavior:

1. validates `config.yaml`,
2. applies migrations from `backend/src/migrations` (currently baseline-only: `001_init_schema.up.sql`),
3. ensures schema compatibility,
4. optionally starts local Alertmanager helper stack,
5. builds and starts backend binary.

## 6. Build and test commands

From `backend/src`:

```bash
go mod tidy
go build -o ../server ./cmd/server
go test ./...
```

## 7. Logging and diagnostics

Operational diagnostics:

- structured JSON logs via `slog`,
- per-request logging middleware with route pattern and trace ID,
- audit/event stream for operational actions,
- standardized API error payloads (including `errorId` on server errors).

## 8. Operational caveats

1. Running with too many DB connections can exhaust PostgreSQL slots; tune `DB_MAX_*`.
2. In development, insecure cookie mode requires explicit opt-in (`auth.allow_insecure_cookies=true`).
3. For production, use HTTPS and production-grade secrets.

## 9. Docker image (backend)

Build image from `src/ctwall`:

```bash
# Option A: build local image
docker build -t ctwall-backend:local -f backend/docker/Dockerfile backend

# Option B: pull published image
docker pull cybergabisoft/ctwall-backend:1.0.0
```

Run backend via Docker Compose (recommended):

```bash
mkdir -p "$(pwd)/deploy/docker/backend-config"
chmod 0777 "$(pwd)/deploy/docker/backend-config"
chmod 0666 "$(pwd)/deploy/docker/backend-config/config.yaml"
chmod 0666 "$(pwd)/deploy/docker/backend-config/alertmanager.yml"

# If using local build:
#   set CTWALL_BACKEND_IMAGE=ctwall-backend:local in ./deploy/docker/.env

docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env up -d \
  ctwall-postgres ctwall-alertmanager ctwall-backend

docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env logs -f ctwall-backend
```

Notes:

- Container defaults are:
  - `CTWALL_CONFIG_PATH=/app/config/config.yaml`
  - `CTWALL_SECRETS_PATH=/app/config/secrets.yaml`
  - `CTWALL_CONFIG_TEMPLATE_PATH=/app/config.template.yaml`
  - `ALERTMANAGER_CONFIG_FILE_PATH=/app/config/alertmanager.yml`
- Runtime config file should stay non-secret and contain only operational settings.
- Backend writes resolved/generated runtime secrets to `CTWALL_SECRETS_PATH`.
- Runtime data path defaults to `/app/data/blob_storage` via bundled config.
- On first run backend can generate missing runtime secrets directly in `CTWALL_SECRETS_PATH`.
- Startup SQL migrations can be auto-applied by backend when:
  - `database.auto_apply_on_start=true`,
  - `database.migrations_path` points to directory with `*.up.sql` files.
- Current baseline keeps a single migration file: `001_init_schema.up.sql`.
- Relative migration paths resolve against config file directory.
- Docker image bundles migrations under `/app/src/migrations`.
- Full local stack with the same file-based model is available in `src/ctwall/docker-compose.yml`.

## 10. Helm chart (backend)

Chart location:

- `backend/helm/ctwall-backend`

Validation:

```bash
docker run --rm -v "$PWD/helm/ctwall-backend:/chart" alpine/helm:3.17.2 lint /chart
docker run --rm -v "$PWD/helm/ctwall-backend:/chart" alpine/helm:3.17.2 template ctwall-backend /chart
```

Install:

```bash
helm upgrade --install ctwall-backend ./helm/ctwall-backend -n ctwall --create-namespace
```

Runtime chart behavior:

- uses ConfigMap-provided bootstrap config source,
- uses runtime config from `/app/config/config.yaml` (bootstrapped from `/app/config.template.yaml` when missing),
- persists runtime secrets in `/app/config/secrets.yaml`,
- writes/render internal Alertmanager config to `/app/config/alertmanager.yml`,
- can deploy internal PostgreSQL via `postgresql.enabled=true` (default),
- can use external PostgreSQL via `postgresql.enabled=false` + `config.database.url`,
- supports loading backend config from an edited file via Helm `--set-file configRaw=...`,
- supports split Helm values model:
  - non-secret values file (for service/resources/feature toggles),
  - optional separate secrets values file (for PostgreSQL password),
- provisions PVC for `/app/config` (unless existing claim is provided),
- provisions PVC for `/app/data` (unless existing claim is provided),
- exposes service on port `8080`.
