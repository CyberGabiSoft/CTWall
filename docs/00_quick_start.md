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

## Quick start (Docker Compose) - localhost

Run from `src/ctwall`:

**For production complete: `Before Production (Required)`.**

### 1. Get container images

#### Pull published images (default in deploy/docker/.env)
```bash
docker pull cybergabisoft/ctwall-backend:1.0.0
docker pull cybergabisoft/ctwall-frontend:1.0.0
```

OR

#### (optional): Build local images and override tags in deploy/docker/.env
```bash
docker build -t ctwall-backend:local -f backend/docker/Dockerfile backend
docker build -t ctwall-frontend:local -f frontend/docker/Dockerfile frontend
```


### 2. Start full stack (by default uses images from dockerhub)
**Warning: This uses the default PostgreSQL credentials. Please change them before the first startup in a production environment.**
```bash
docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env up -d
```

### 3. Get admin credentials
```bash
docker run --rm -v ctwall_ctwall-backend-data:/data busybox:1.37.0 cat /data/bootstrap-admin-credentials.json
```

Open UI at:

```text
https://127.0.0.1:8443
```

### 4. Interact
```bash
Create product -> Create scope -> Import SBOM
```

### 5. Stop full stack
```bash
docker compose -f ./docker-compose.yml --env-file ./deploy/docker/.env down
```

### (Optional) Use external PostgreSQL with Docker Compose

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


## Quick start (Helm, unified chart)

Run from `src/ctwall`.

**For production complete: `Before Production (Required)`.**

This Helm flow matches Docker Compose behavior: one chart deploys backend + frontend and can also run PostgreSQL.

### 1. Prepare cluster namespace, chart and build dependencies:
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

### 2. Install full stack from one chart:
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
  --set backend.image.repository=docker.io/cybergabisoft/ctwall-backend \
  --set backend.image.tag=1.0.0 \
  --set frontend.image.repository=docker.io/cybergabisoft/ctwall-frontend \
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

### 3. Get bootstrap admin credentials after Helm install (one-liner):
```bash
NS="${NS:-ctwall}"; POD="$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=backend -o jsonpath='{.items[0].metadata.name}')"; EC="admin-creds-$(date +%s)"; kubectl -n "$NS" debug "$POD" --profile=restricted --target=backend --image=busybox:1.37.0 -c "$EC" --quiet -- cat /proc/1/root/app/data/bootstrap-admin-credentials.json >/dev/null; for i in $(seq 1 20); do OUT="$(kubectl -n "$NS" logs "$POD" -c "$EC" --tail=20 2>/dev/null)" && [ -n "$OUT" ] && { echo "$OUT"; break; }; sleep 1; done
```

Why this is needed: backend image is distroless (no `cat`/`sh`), so direct `kubectl exec ... cat` will fail.
`bootstrap-admin-credentials.json` contains bootstrap/recovery password and can become outdated after password change in UI/API.

If your kubectl binary is not named `kubectl`, pass it via `KUBECTL` (for example `KUBECTL="microk8s kubectl"`).

### 4. Ingress (optional)
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

### 5. Interact
```bash
Create product -> Create scope -> Import SBOM
```

### (Optional) Helm with external PostgreSQL

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