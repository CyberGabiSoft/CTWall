
## Before Production (Required)

Do not start CTWall with default credentials or local-dev flags in shared/prod environments.

### Runtime Secrets Model (Required)

On first successful startup, backend initializer generates runtime secrets and persists them to `secrets.yaml`:
- `jwt_secret_key`
- `app_encryption_passphrase`
- `app_encryption_salt`
- `alertmanager_username`
- `alertmanager_password`

Rules:
1. Persist and back up this file/volume. Losing it means loss of decryption continuity for encrypted connector secrets.
2. Do not manually rotate `app_encryption_passphrase` or `app_encryption_salt` on running environments unless you also re-encrypt connector secrets.
3. Never keep placeholder/demo values in production.

### Docker Compose (Required)

Checklist (`src/ctwall/deploy/docker`):

1. Update PostgreSQL password in `.env`:
   - `POSTGRES_PASSWORD` must not be `change-me-postgres`.
2. Keep database credentials in one place: `deploy/docker/.env` only:
   - `POSTGRES_PASSWORD` (required),
   - `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`,
   - `POSTGRES_SSLMODE` (`require` in non-local environments).
   - Docker Compose builds backend `DB_URL` automatically from these values.
3. Disable local-dev connector relaxations in `.env`:
   - `ALERTING_ALLOW_INSECURE_SMTP=false`
   - `ALERTING_ALLOW_HTTP_TARGETS=false`
   - `ALERTING_ALLOW_LOCALHOST_TARGETS=false`
4. Set proper public URL in `.env`:
   - `CTWALL_ALERTING_PUBLIC_BASE_URL` must point to your real HTTPS CTWall URL (not localhost).
5. Configure Alertmanager safely in `backend-config/alertmanager.yml`:
   - do not keep test/demo webhook or token values.
   - use real receiver endpoints for your environment.
6. Keep backend data volume persistent and protected:
   - runtime secrets and bootstrap credentials are stored in backend data volume.
   - avoid `docker compose down -v` on persistent/prod environments.
7. Use trusted TLS certs for frontend in non-local environments:
   - avoid self-signed runtime defaults.
   - provide cert/key and set `FRONTEND_SSL_AUTO_GENERATE=false`.
8. Use pinned image tags:
   - avoid mutable `latest` in production-like environments.
9. After first login:
   - rotate `admin@ctwall` password immediately.
   - restrict access to generated files (runtime secrets and bootstrap credentials in backend data volume).

### Helm Chart (Required)

Checklist (`src/ctwall/helm/ctwall`):

1. Set PostgreSQL auth values before install:
   - `global.postgresql.auth.password`
   - never keep `change-me-postgres`.
2. If using external PostgreSQL:
   - set `postgresql.enabled=false`
   - set both:
     - `backend.env.DB_URL`
     - `backend.config.database.url`
   - point to external DB with TLS-enabled DSN.
3. Set trusted frontend TLS secret:
   - replace local self-signed certs with CA/trusted certs for real deployments.
4. Use pinned image tags:
   - explicitly set backend/frontend image tags instead of `latest`.
   - initializer runs from the same backend image with `CTWALL_INIT_ONLY=true`.
5. Keep backend config/data persistence enabled and protected:
   - `configPersistence.enabled=true` and `persistence.enabled=true` must remain enabled for production.
   - runtime `secrets.yaml` is stored on backend config volume and must survive pod restarts/upgrades.
6. After first startup:
   - rotate bootstrap admin password immediately.
