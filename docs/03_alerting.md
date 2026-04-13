## Alerting model (Alertmanager + connectors)

CTWall alerting is built around an Alertmanager-centric runtime:

1. CTWall creates/updates alert groups and occurrences from malware analysis results.
   - Malware alerts support two independent detection modes:
     - `purl_version_smart` (default enabled),
     - `purl_contains_prefix` (default disabled).
   - Mode eligibility is match-type aware:
     - `EXACT` findings map to `purl_version_smart`,
     - `CONTAINS_PREFIX` findings map to `purl_contains_prefix`.
   - Each mode has independent per-project alert severity (`ERROR/WARNING/INFO`).
   - `purl_contains_prefix` supports optional per-project lookback window:
     - `lookbackDays = NULL` -> all history,
     - `lookbackDays > 0` -> only OSV entries from last `N` days by `modified_at` (fallback `published_at`).
     - If an OSV entry has no `modified_at` and no `published_at`, date filtering is not enforced for that entry.
   - Mode is encoded into malware group key (`detect_mode:...`) so both modes can emit separate alerts for the same malware PURL.
   - Group severity is synchronized with active mode severity on both reconcile and occurrence upsert paths.
2. Backend emits FIRING/RESOLVED lifecycle signals with dedup context.
3. Connectors are dispatched in one best-effort cycle (Slack, Discord, SMTP, SNS, Jira, and optional external Alertmanager).
4. Failure on one connector does not block successful delivery on other enabled connectors.

Why Alertmanager is used:

1. one normalized alert lifecycle model across channels,
2. consistent handling of alert state transitions (FIRING -> RESOLVED),
3. operationally simpler routing/integration control at deployment level.
