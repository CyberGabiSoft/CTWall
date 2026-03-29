# Security and Integrations (Operational View)

## 1. Operational security behavior

Backend runtime provides:

1. authenticated API access for users and service accounts,
2. role-based authorization (global and project scope),
3. standardized API error payloads for troubleshooting,
4. event/audit visibility for high-signal operations.

From an operator perspective, the important inputs are:

- proper TLS at ingress/reverse-proxy level,
- valid secrets in environment variables,
- role assignments matching least-privilege policy.

## 2. Connector scope (MVP)

Currently exposed connectors:

- `DISCORD`
- `SMTP`
- `JIRA`
- `ALERTMANAGER_EXTERNAL`
- `SLACK`
- `SNS`

Connector availability is managed centrally and can be extended in future releases.

## 3. Alerting runtime behavior

Alert processing includes:

1. group/occurrence aggregation,
2. dedup rule evaluation,
3. connector dispatch attempts across all enabled channels in one cycle (best-effort fan-out),
4. retry/dead-letter only when no channel accepted delivery,
5. per-channel failure audit events for operational debugging.

## 4. Jira runtime behavior

Jira integration supports:

1. project-scoped settings with precedence (project/product/scope/test),
2. metadata refresh used by UI forms,
3. issue mapping and delivery attempt history,
4. issue lifecycle updates aligned with alert state changes,
5. per-entity internal retry policy (`delivery_retry_attempts`, `delivery_retry_backoff_seconds`),
6. manual Jira redelivery enqueue endpoint per entity (`/data/products|scopes|tests/{id}/jira/retry`) for selected `alertGroupId`.

## 5. External Alertmanager behavior

When external Alertmanager connector is configured:

1. CTWall sends alert payloads to configured external endpoint,
2. external delivery failures are tracked without blocking successful delivery on other enabled connectors,
3. test connection validates endpoint reachability and credentials.

## 6. OSV and malware analysis operations

OSV source operations include:

1. full sync,
2. incremental sync,
3. recompute runs.

Operational state is visible in:

- source history,
- sync failures,
- posture/explorer results derived from processed data.

## 7. Production operations checklist

1. Use HTTPS for all public and internal entry points.
2. Keep JWT and encryption secrets rotated and stored in secret manager.
3. Monitor connector dead-letter and sync-failure events.
4. Keep DB connection pool settings within PostgreSQL capacity.
5. Validate connector credentials after every rotation.
