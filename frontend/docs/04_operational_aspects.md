# Operational Aspects

## 1. Access control behavior

1. Unauthenticated users can access only `/login`.

2. Admin-only routes:
- `/admin/projects`
- `/admin/settings/*`

3. Section actions are enabled/disabled based on global role and active project role.

## 2. Project context

Frontend keeps current project context:

- available projects for current user,
- selected project (id/name),
- effective project permissions.

Project switch behavior:

- persists selected project via API,
- refreshes events badge,
- forces workspace reload to `/dashboard`.

## 3. Refresh and state synchronization

## 3.1 Global header refresh

Open events count refreshes:

- on each navigation,
- every 30s (polling),
- after explicit event updates.

## 3.2 Search

- top-bar query is synchronized with URL for `/search/components`,
- submit requires minimum 2 characters.

## 3.3 Feature section loading

Most sections follow a common loading lifecycle:

1. loading -> spinner,
2. error -> error panel,
3. loaded -> table/cards/forms,
4. explicit `Refresh/Reload` actions in section headers.

## 4. Runtime navigation UX

1. Sidebar behavior
- Data/Security/Settings groups toggle submenu and keep active state from URL.

2. Shared table behavior
- common `app-data-table` supports:
  - sorting,
  - basic and advanced filtering,
  - column configuration,
  - pagination,
  - export.

3. Success feedback
- global success-feedback interceptor is used,
- many mutating flows also show explicit snack-bar confirmations.

## 5. Special pages

1. `forbidden`
- no-access page (`/forbidden`).

2. `change-password`
- password change form;
- service account is blocked.

3. `login`
- public page outside authenticated shell.

## 6. Important limitations and notes

1. Project permissions are always evaluated against currently active project.

2. Security Sources is global-admin controlled (not project-role controlled).

3. Some UI texts may be stricter/more user-facing than backend authorization responses.

4. Global PURL search is not in left menu; it is initiated from top header search.

5. In Test Details (`Data -> Components`), `Load all` uses a single `GET /api/v1/tests/{testId}/components?all=true` call and consumes inline malware snapshot fields (`malwareVerdict`, `malwareScannedAt`, `malwareValidUntil`, `malwarePurls`) from that payload, so the UI does not issue per-component findings/queue follow-up requests.

## 7. Docker runtime

Frontend containerization uses multi-stage build:

1. Build stage (`node:22-alpine`)
- installs dependencies from `src/package-lock.json` with `npm ci`,
- builds production assets via `npm run build`.

2. Runtime stage (`nginx:1.27-alpine`)
- serves static app from `/usr/share/nginx/html`,
- uses SPA fallback (`try_files ... /index.html`),
- proxies `/api/*` to backend,
- serves frontend only on HTTPS port (no HTTP listener).

Files:

- `src/frontend/docker/Dockerfile`
- `src/frontend/docker/nginx.conf.template`
- `src/frontend/.dockerignore`

Runtime variable:

- `BACKEND_UPSTREAM` (default: `http://127.0.0.1:8080`)
- `FRONTEND_CLIENT_MAX_BODY_SIZE` (default: `50m`)
  - nginx `client_max_body_size` applied on both HTTP and HTTPS frontend listeners.
- `FRONTEND_SSL_PORT` (default: `443`)
- `FRONTEND_SSL_CERT_PATH` (default: `/etc/nginx/certs/tls.crt`)
- `FRONTEND_SSL_KEY_PATH` (default: `/etc/nginx/certs/tls.key`)
- `FRONTEND_SSL_AUTO_GENERATE` (default: `true`)
- `FRONTEND_SSL_SELF_SIGNED_CN` (default: `localhost`)
- `FRONTEND_SSL_SELF_SIGNED_DAYS` (default: `365`)

TLS helper scripts:

- `src/frontend/docker/generate_selfsigned.sh` for local certificate generation,
- `src/frontend/docker/05-ensure-certs.sh` for startup cert bootstrap (auto-generate when enabled),
- `src/frontend/docker/10-validate-certs.sh` for runtime cert/key validation at container start.

TLS behavior at container startup:

1. If cert/key files exist on `FRONTEND_SSL_CERT_PATH` / `FRONTEND_SSL_KEY_PATH`, they are used as-is.
2. If files are missing and `FRONTEND_SSL_AUTO_GENERATE=true`, container generates self-signed certs automatically.
3. If files are missing and `FRONTEND_SSL_AUTO_GENERATE=false`, startup fails and user must provide valid cert/key files.

## 8. Helm deployment

Frontend chart is available at:

- `src/frontend/helm/ctwall-frontend`

The chart deploys:

1. `Deployment` with nginx-based frontend container.
2. `Service` exposing HTTPS on port `443` and internal HTTP on port `80` (for ingress backend traffic).
3. Optional `Ingress` and `HPA`.
4. Optional `PodDisruptionBudget`.
5. Helm test pod (`wget`) for service connectivity.

Key runtime value:

- `env.BACKEND_UPSTREAM`
  - injected into container as environment variable used by nginx template for `/api/*` proxy.
- `tls.existingSecret`
  - Kubernetes TLS Secret mounted into the pod as frontend certificate/key.
  - set empty when relying on runtime self-signed generation (`FRONTEND_SSL_AUTO_GENERATE=true`).
- `ingress.backendServicePortName`
  - default `http` so ingress controllers can route to frontend internal HTTP backend and avoid TLS validation issues on pod self-signed certs.
- `ingress.annotations.nginx.ingress.kubernetes.io/proxy-body-size`
  - default `50m` to match backend ingest upload limit for SBOM payloads.
