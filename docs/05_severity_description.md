
## Severity model (alerts vs logs)
CTWall uses two different severity domains:

1. `alert severity` for security findings and connector dispatch decisions,
2. `log level` for application observability and troubleshooting.

Alert severity values:

1. `INFO`
2. `WARN`
3. `ERROR`

In dedup/Jira threshold settings, severity is shown as:

1. `INFO`
2. `WARNING`
3. `ERROR`

`WARNING` (settings/UI) is equivalent to `WARN` (stored alert group severity).

System log levels:

1. `DEBUG`
2. `INFO`
3. `WARN`
4. `ERROR`

Key difference:

1. Alert severity describes business/security importance of an alert group (`alert_groups`, connector notifications).
2. Log level describes verbosity/criticality of runtime diagnostics in backend logs.
3. They are independent; changing logger level does not change computed alert severity.
4. Debug logs do not create alerts by themselves.

For logging conventions, see: `DOCS/best_practices/observability_standards.md`.
