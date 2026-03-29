# Security Feature

UI for security posture, intelligence sources, and alert listings.

## Routes

- `/security/posture` (default) - placeholder (TBD)
- `/security/sources` - manage malware sources + trigger sync + recompute operations + history tables
- `/security/explorer` - Explorer: malware summary, analysis runs, detail, and schedule configuration (inside Analysis tab)
- `/security/alerts` - placeholder (TBD)

## API Mapping

- `GET /api/v1/explorer/sources`
- `PATCH /api/v1/explorer/sources/{sourceId}`
- `GET /api/v1/explorer/findings?sourceId=...`
- `POST /api/v1/explorer/osv/download_all`
- `POST /api/v1/explorer/osv/download_latest`
- `GET /api/v1/explorer/sources/{sourceId}/sync-history`
- `GET /api/v1/explorer/sources/{sourceId}/sync-history/{syncId}/errors`
- `POST /api/v1/explorer/sources/{sourceId}/results/recompute`
- `GET /api/v1/explorer/sources/{sourceId}/results/recompute-history`
- `POST /api/v1/component-analysis/explorer/summary/recompute`
- `GET /api/v1/component-analysis/explorer/summary/recompute-history`
- `GET /api/v1/component-analysis/explorer/schedule`
- `PATCH /api/v1/component-analysis/explorer/schedule`

## Notes

- OSV is the first supported source.
- History tables mirror the Data tables (filters, column selection, pagination).
