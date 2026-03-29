# CTWall - ChainThreatWall
<div align="center">
![CTWall Logo](./docs/images/ctwall-logo.png)
</div>
**CTWall(ChainThreatWall)** platform helps Security, DevOps, and Product teams make faster risk decisions in the software supply chain based on SBOM/BOM data.

This tool helps You to:
1. Get dependency risk visibility in one place.
2. React faster to malware threats.
3. Keep history and evidence for audits.
4. Reduce manual triage effort.

To ingest SBOMs into the platform, you can use DepAlert. [Depalert](https://github.com/CyberGabiSoft/DepAlert)

![CTWall Dashboard](./docs/images/ctwall-dashboard.png)
![CTWall Alerts](./docs/images/ctwall-alert.png)

## Platform purpose

CTWall gives security and platform teams one operational place to:

1. Ingest SBOMs from CI/CD and vendor channels.
2. Keep revision history for each Product / Scope / Test.
3. Map components to malware intelligence and triage findings.
4. Monitor posture and trends on project dashboards.
5. Dispatch operational alerts to connectors (Jira, SMTP, Slack, SNS, external Alertmanager).

![CTWall Connectors](./docs/images/ctwall-connectors.png)

## What happens in runtime

Typical flow:

1. SBOM is uploaded (or sent by agent).
2. Revision and components are persisted.
3. Background workers perform malware analysis.
4. Alert groups/occurrences are updated.
5. Configured connectors receive FIRING/RESOLVED signals,
6. UI presents dashboards, posture, explorer, and triage state.

CTWall is a practical supplement to classic SCA (Software Composition Analysis): it adds malware-focused detection in the software supply chain layer. By using free/public threat intelligence sources (for now it is only publicly available OSV database from https://osv.dev/), teams can generate notifications about newly observed dependency threats without building a custom intel pipeline from scratch.

![CTWall SBOM Dependency Graph](./docs/images/ctwall-dependency-graph.png)

## Business Problems CTWall Solves

1. **No continuous dependency risk monitoring (application + infrastructure).**
CTWall collects SBOM/BOM data and organizes it in one model: Product -> Scope -> Test. In today's threat landscape, lack of continuous monitoring and delayed response to dependency threats can lead to compromise of both applications and infrastructure.

2. **Late threat detection and reaction.**
SBOM import and analysis help detect risk before production or early in the delivery cycle. In practice, CTWall supports earlier detection of malware packages across both application dependencies and infrastructure-related dependencies.

3. **Fragmented alerts and communication noise.**
CTWall normalizes alerts and can send them to operational tools (for example Jira, Slack, SMTP, Alertmanager), instead of relying only on CI logs.

4. **Hard audits and missing decision history.**
The platform stores SBOM revision history and events, making it easier to audit and reconstruct what changed and when.

5. **Too much manual triage.**
Teams get structured results and can move faster from alert to decision.

### Some Attack Examples CTWall Can Help You Detect

CTWall helps by correlating SBOM/BOM components with threat intelligence and malware advisories, then generating operational alerts.

1. **September 2025 npm supply chain campaign (Shai-Hulud + cryptojacking payloads).**
Phishing-led maintainer compromise, malicious package updates, credential/token theft, and CI/CD persistence were publicly documented in sector advisories.

2. **July 2025 PyPI phishing incident with malicious `num2words` releases (0.5.15, 0.5.16).**
Compromised maintainer account led to malicious package versions being published and later removed.

3. **November 2025 PyPI typosquatting campaign (`tableate`, MAL-2025-191535).**
Public OSV records describe RAT-like behavior and second-stage payload delivery.

4. **March 2026 PyPI malware case (`amigapythonupdater`, MAL-2026-1136).**
Public OSV records describe exfiltration of environment variables/cloud tokens and command execution behavior.

5. **February 2026 npm malware case (`test-npm-style`, MAL-2026-771).**
Public OSV/GHSA-linked records classify affected versions as malicious and recommend immediate secret rotation.

## Applicaiton Flow

```mermaid
flowchart LR
    A[Product / Source] --> B[Generate SBOM/BOM]
    B --> C[Import SBOM/BOM file to CTWALL]
    C --> D[Alert]
```

## What Matters To Get Started Quickly

1. Start with one product and one pipeline.
A small, controlled rollout gives fast feedback with low rollout risk.

2. Standardize SBOM/BOM input format.
The easiest start is CycloneDX or Syft/Trivy JSON and one agreed format per team.

3. Connect only one alert channel first.
Usually Jira or Slack, to speed up adoption and avoid noise.

4. Define clear owners (business + technical).
An alert without an owner usually gets no action.

5. Set a lightweight operating rhythm.
For example, a daily review of new alerts and a weekly risk trend review.

6. Treat SBOM as a continuous process, not a one-time report.
The biggest value comes from regular imports and revision comparison.

## Repository layout
- Backend: `backend`
- Frontend: `frontend`
- Unified Helm chart (backend + frontend + optional PostgreSQL): `helm/ctwall`

## Other tools
- Agent (DepAlert CLI): available as image `docker.io/cybergabi/depalert` (optional)


## Quick start (Docker Compose) - localhost

Run from `src/ctwall`:

**For production complete: `Before Production (Required)`.**

### 0) Prepare env files and permissions:

```bash
chmod 0777 deploy/docker/backend-config
chmod 0666 deploy/docker/backend-config/config.yaml
chmod 0666 deploy/docker/backend-config/alertmanager.yml
```


### 1a) Pull published images (default in deploy/docker/.env)
```bash
docker pull cybergabi/ctwall-backend:1.0.0
docker pull cybergabi/ctwall-frontend:1.0.0
```

### 1b) (optional): build local images and override tags in deploy/docker/.env
```bash
docker build -t ctwall-backend:local -f backend/docker/Dockerfile backend
docker build -t ctwall-frontend:local -f frontend/docker/Dockerfile frontend
```


### 2) Start full stack (by default uses images from dockerhub)
**Warning: This uses the default PostgreSQL credentials. Please change them before the first startup in a production environment.**
```bash
docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env up -d
```

### 3) Get admin credentials
```bash
docker run --rm -v ctwall_ctwall-backend-data:/data busybox cat /data/bootstrap-admin-credentials.json
```

Open UI at:

```text
https://127.0.0.1:8443
```

### 4) Stop full stack
```bash
docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env down
```

## Quick start (Helm, unified chart)

Run from `src/ctwall`.

**For production complete: `Before Production (Required)`.**

This Helm flow matches Docker Compose behavior: one chart deploys backend + frontend and can also run PostgreSQL.

### 0) Prepare cluster namespace, chart and build dependencies:
```bash
export NS=ctwall
helm repo add bitnami https://charts.bitnami.com/bitnami
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
helm dependency build ./helm/ctwall
```
Note:
`helm dependency build ./helm/ctwall` is enough for direct install from source path (`helm upgrade --install ... ./helm/ctwall`).

Build packaged chart (`.tgz`):
```bash
helm package ./helm/ctwall --destination ./helm/dist
```
Result file (for current chart version):
```text
./helm/dist/ctwall-1.0.0.tgz
```

For local/testing only: if you do not have `./tls/tls.crt` and `./tls/tls.key` yet, generate self-signed certs:
```bash
./frontend/docker/generate_selfsigned.sh ./tls localhost 365
```

Create frontend TLS secret (default frontend chart uses `tls.existingSecret=ctwall-frontend-tls`):
```bash
kubectl -n "$NS" create secret tls ctwall-frontend-tls \
  --cert=./tls/tls.crt \
  --key=./tls/tls.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

### 1) Install full stack from one chart:
**Warning: This uses the default PostgreSQL credentials. Please change them before the first startup in a production environment.**

#### Option A) Install with defaults
```bash
helm upgrade --install ctwall ./helm/ctwall -n "$NS"
```

Note: this command creates Services. Frontend Ingress is optional and disabled by default (`frontend.ingress.enabled=false`).
See `Ingress (optional)` below to enable it.

#### Option B) Install full stack with explicit public image tags:
```bash
helm upgrade --install ctwall ./helm/ctwall -n "$NS" \
  --set backend.image.repository=docker.io/cybergabi/ctwall-backend \
  --set backend.image.tag=1.0.0 \
  --set frontend.image.repository=docker.io/cybergabi/ctwall-frontend \
  --set frontend.image.tag=1.0.0
```

#### Option C) Install full stack with explicit manually built images (for example after local `docker build`):
```bash
helm upgrade --install ctwall ./helm/ctwall -n "$NS" \
  --set backend.image.repository=ctwall-backend \
  --set backend.image.tag=local \
  --set backend.image.pullPolicy=IfNotPresent \
  --set frontend.image.repository=ctwall-frontend \
  --set frontend.image.tag=local \
  --set frontend.image.pullPolicy=IfNotPresent
```

Default behavior:
1. deploys backend and frontend from one release (`ctwall`),
2. deploys PostgreSQL in-cluster from `bitnami/postgresql` (`postgresql.enabled=true`),
3. backend init flow generates runtime secrets on first start in backend config volume.

### 2) Get bootstrap admin credentials after Helm install (one-liner):
```bash
NS="${NS:-ctwall}"; POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=backend -o jsonpath='{.items[0].metadata.name}')"; EC="admin-creds-$(date +%s)"; kubectl -n "$NS" debug "$POD" --profile=restricted --target=backend --image=busybox:1.36 -c "$EC" --quiet -- cat /proc/1/root/app/data/bootstrap-admin-credentials.json >/dev/null; for i in $(seq 1 20); do OUT="$(kubectl -n "$NS" logs "$POD" -c "$EC" --tail=20 2>/dev/null)" && [ -n "$OUT" ] && { echo "$OUT"; break; }; sleep 1; done
```

Why this is needed: backend image is distroless (no `cat`/`sh`), so direct `kubectl exec ... cat` will fail.
`bootstrap-admin-credentials.json` contains bootstrap/recovery password and can become outdated after password change in UI/API.

If your kubectl binary is not named `kubectl`, pass it via `KUBECTL` (for example `KUBECTL="microk8s kubectl"`).

### 3) Ingress (optional)
Unified chart exposes only frontend via Ingress. Backend API stays internal (ClusterIP service only).
Frontend ingress is disabled by default; enable it when you want HTTP(S) access via an ingress controller
(for example `ingress-nginx`).

Ensure an ingress controller is installed in your cluster:
```bash
kubectl get ingressclass
```

Generate a self-signed TLS certificate (for local ingress TLS):
```bash
./frontend/docker/generate_selfsigned.sh ./tls localhost 365
```

For Helm/Kubernetes, runtime auto-generation should remain disabled (`FRONTEND_SSL_AUTO_GENERATE=false`, default).
Frontend should consume certificate/key from Kubernetes TLS Secret (`tls.existingSecret`), not create certs inside pod.

Enable frontend ingress:

```bash
helm upgrade --install ctwall ./helm/ctwall -n ctwall \
  --set frontend.ingress.enabled=true \
  --set frontend.service.httpEnabled=true \
  --set frontend.ingress.backendServicePortName=http \
  --set frontend.ingress.hosts[0].host=ctwall-frontend.local \
  --set frontend.ingress.hosts[0].paths[0].path=/ \
  --set frontend.ingress.hosts[0].paths[0].pathType=Prefix \
  --set frontend.ingress.tls[0].hosts[0]=ctwall-frontend.local \
  --set frontend.ingress.tls[0].secretName=ctwall-frontend-tls
```

`ingress.className` is optional. If your cluster has a default IngressClass, leave it unset.
For MicroK8s Traefik ingress, keep `frontend.service.httpEnabled=true` and `frontend.ingress.backendServicePortName=http`
to terminate TLS on ingress and forward plaintext HTTP to frontend service inside cluster.

Local hosts entry (optional convenience):

```bash
echo "127.0.0.1 ctwall-frontend.local" | sudo tee -a /etc/hosts
```

If `https://127.0.0.1` returns `404 page not found`, it is usually host mismatch (ingress is host-based).
Use `https://ctwall-frontend.local` (or set `Host: ctwall-frontend.local`).


### Helm with external PostgreSQL

Use this mode when your PostgreSQL is managed outside this chart.

1. Prepare external DB connection values (recommended via separate values file):

```yaml
# deploy/helm/values.external-postgres.yaml
postgresql:
  enabled: false

backend:
  env:
    DB_URL: "postgres://appuser:STRONG_PASSWORD@your-postgres-host:5432/appdb?sslmode=require"
  config:
    database:
      url: "postgres://appuser:STRONG_PASSWORD@your-postgres-host:5432/appdb?sslmode=require"
```

2. Install/upgrade with external DB values:

```bash
helm upgrade --install ctwall ./helm/ctwall -n "$NS" \
  -f ./deploy/helm/values.external-postgres.yaml
```

3. Validate that bundled PostgreSQL is not deployed:

```bash
kubectl -n "$NS" get pods | grep postgresql || echo "OK: bundled PostgreSQL not deployed"
```

Notes:
1. Set both `backend.env.DB_URL` and `backend.config.database.url` to the same DSN.
2. Use TLS-enabled DSN in non-local environments (for example `sslmode=require`).
3. Ensure external DB already exists and backend user has schema/table create privileges for first startup.

Check rollout:
```bash
kubectl -n "$NS" rollout status deploy/ctwall-backend
kubectl -n "$NS" rollout status deploy/ctwall-frontend
```

### Use external PostgreSQL with Docker Compose

Run from `src/ctwall`.

1. Point backend config to your external database in `deploy/docker/backend-config/config.yaml`:

```yaml
database:
  url: "postgres://USER:PASSWORD@YOUR-DB-HOST:5432/YOUR_DB?sslmode=require"
```

2. Start stack in external-DB mode (bundled PostgreSQL disabled):

```bash
docker compose \
  -f ./docker-compose.yml \
  -f ./docker-compose.external-postgres.yml \
  --env-file ./deploy/docker/.env up -d
```

3. Verify services:

```bash
docker compose \
  -f ./docker-compose.yml \
  -f ./docker-compose.external-postgres.yml \
  --env-file ./deploy/docker/.env ps
```

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

Where `secrets.yaml` is for Docker Compose:
1. Runtime path is `/app/data/secrets.yaml` (`CTWALL_SECRETS_PATH` in `docker-compose.yml`).
2. It is stored in named volume `ctwall_ctwall-backend-data` (not in `.env`).
3. Read current values with:
   ```bash
   docker run --rm -v ctwall_ctwall-backend-data:/data busybox:1.36 cat /data/secrets.yaml
   ```
4. Treat this file as runtime-managed by initializer (do not edit manually in normal operation).

1. Update PostgreSQL password in `.env`:
   - `POSTGRES_PASSWORD` must not be `change-me-postgres`.
2. Update backend DB DSN in `backend-config/config.yaml`:
   - `database.url` must match real DB credentials and host.
   - use TLS-enabled DSN in non-local environments (for example `sslmode=require`).
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
   - `postgresql.auth.password`
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
