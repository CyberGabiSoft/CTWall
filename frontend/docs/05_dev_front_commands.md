# Commands (ctwall frontend)

All commands should be run from:
`/home/mz/projects/project0/src/frontend/front0/ctwall`

## Install

```bash
npm install
```

## Development server

```bash
npm run start
```

This uses `proxy.conf.json` to forward `/api/*` to `http://127.0.0.1:8080`.

Custom host/port:

```bash
npm run start -- --host 127.0.0.1 --port 4201 --no-open
```

Quick health check (start + stop):

```bash
./scripts/check-dev-server.sh
```

## Build

```bash
npm run build
```

Watch mode:

```bash
npm run watch
```

## Lint (a11y + security)

```bash
npm run lint
```

## Tests

### Hybrid approach

We use **Vitest** for fast unit tests (logic, stores, utils) and **Angular TestBed** via `ng test` for component/integration specs.

- `*.test.ts` → Vitest (fast unit tests)
- `*.spec.ts` → Angular TestBed (`ng test`)

Full policy: see `testing_policy.md`.

Vitest (fast unit tests):

```bash
npm run test
```

Vitest watch:

```bash
npm run test:watch
```

Angular test runner (if needed):

```bash
npm run test:ng
```

## Local auth setup (GUI)

To obtain working login cookies for HTTP (local dev), use:

```bash
../../../../manual-test-scripts/run_users.sh
```

This script starts the backend with insecure cookies **only for local dev** and prints admin credentials.
