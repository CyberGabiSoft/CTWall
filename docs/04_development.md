## Development/running applicaitons manually

## Backend module (source mode, optional)

Run from `src/ctwall`:

```bash
cd backend/src
go mod tidy
go build -o ./backend_server ./cmd/server
go test ./...
./backend_server
```

Notes:

1. runtime config file: `backend/config.yaml`,
2. runtime secrets are generated/persisted in `/app/data/secrets.yaml` for Docker Compose mode,
3. API contract: `backend/api/openapi.yaml`.

## Frontend module (source mode, optional)

Run from `src/ctwall`:

```bash
cd frontend/src
npm ci
npm run start
```

Default dev URL:

```text
http://127.0.0.1:4200
```

Additional frontend checks:

```bash
cd frontend/src
npm run build
npm run lint
npm run test:vitest
```

If you also need a distributable `.tgz` package artifact, run additionally:

```bash
helm package ./helm/ctwall -d ./helm
```