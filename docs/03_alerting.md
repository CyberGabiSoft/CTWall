## Alerting model (Alertmanager + connectors)

CTWall alerting is built around an Alertmanager-centric runtime:

1. CTWall creates/updates alert groups and occurrences from malware analysis results.
2. Backend emits FIRING/RESOLVED lifecycle signals with dedup context.
3. Connectors are dispatched in one best-effort cycle (Slack, Discord, SMTP, SNS, Jira, and optional external Alertmanager).
4. Failure on one connector does not block successful delivery on other enabled connectors.

Why Alertmanager is used:

1. one normalized alert lifecycle model across channels,
2. consistent handling of alert state transitions (FIRING -> RESOLVED),
3. operationally simpler routing/integration control at deployment level.
