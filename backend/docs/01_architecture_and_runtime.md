# Architecture and Runtime

## 1. Runtime scope

Backend application root:

- `src/backend/src`

The backend provides:

1. REST API for CTWall UI and automation clients.
2. Background processing for ingest, malware analysis, and alerting.
3. Integration runtime for Jira and external connectors.

## 2. Startup sequence

At process start, backend:

1. loads configuration from YAML + environment variables,
2. connects to PostgreSQL,
3. applies startup checks and optional SQL migrations,
4. initializes domain services and worker pools,
5. starts HTTP server and readiness/liveness endpoints.

## 3. Request processing model

Each API request follows this operational flow:

1. request enters the HTTP server,
2. authentication and role checks are evaluated,
3. active project context is resolved,
4. domain handler executes business operation,
5. response is returned as JSON or file download.

Error responses use a consistent problem payload shape.

## 4. Background execution model

Backend runs queue workers and schedulers continuously:

1. ingest workers,
2. malware input workers,
3. component analysis workers,
4. revision summary and diff workers,
5. alert dispatch workers.

Worker counts and queue behavior are configurable.

## 5. Source sync model (OSV)

When OSV is enabled, backend runs:

1. full sync loop (long interval),
2. latest/delta sync loop (short interval),
3. recompute operations for already stored results.

All sync states and errors are visible in the Security Sources section.

## 6. Data and migrations

SQL migrations location:

- `src/backend/src/migrations/*.up.sql`
- Current baseline: `src/backend/src/migrations/001_init_schema.up.sql`

Migrations can be applied:

1. by local scripts (`manual-test-scripts/run_server.sh`),
2. automatically on backend startup when enabled in config.

## 7. Build and test

From `src/backend/src`:

```bash
go build ./cmd/server
go test ./...
```
