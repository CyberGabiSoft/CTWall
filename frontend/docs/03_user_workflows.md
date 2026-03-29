# User Workflows

## 1. Start and project selection

1. User signs in at `/login`.
2. After authentication, user lands in app shell (default `/dashboard`).
3. User selects active project in top bar.
4. After project switch, frontend refreshes workspace (`/dashboard`) and reloads scoped data.

## 2. Data -> Browse (products, scopes, tests)

Flow:

1. Open `Data / Browse` (`/data`).
2. Switch section tabs `Products / Scopes / Tests`.
3. Use shared table features (filters, columns, export, pagination, expanded details).
4. Use `Open` to drill down.

Actions (role dependent):

- create: project `WRITER+`,
- delete: project `ADMIN`.
- Jira entity settings dialog (product/scope/test): configure summary template, metadata-driven Jira fields, delivery retry policy (`retry attempts`, `retry backoff seconds`) and run manual `Retry now` from delivery attempts list.

## 3. Data -> Import (SBOM)

Flow:

1. Open `Data / Import` (`/data/import`).
2. Select Product and Scope.
3. Choose test mode:
   - `New test` and enter a name,
   - `Existing test` and select from list.
4. Upload SBOM file (`bom.json`) by drag/drop or file picker.
5. Submit via `Upload SBOM`.

Conditions:

- requires project `WRITER+`,
- read-only mode shows warning and blocks write actions,
- form + file parsing validation runs before upload.

## 4. Data -> Graph

Flow:

1. Open `Data / Graph` (`/data/graph`).
2. Set Product, Scope, Test, SBOM program, Revision, Max nodes.
3. Click `Render graph`.
4. Use tools: zoom, fit, reset, fullscreen, node search.
5. Click node to inspect component details and drill-down actions.

## 5. Data -> User Groups

Flow:

1. Open `Data / User Groups` (`/data/user-groups`).
2. In `Groups` panel, select or create group.
3. In `Group Members`, manage membership and `EDITOR/VIEWER` roles.
4. Save changes.

Rules:

- create group: `WRITER+`,
- member management: project `ADMIN` or group owner with write access.

## 6. Security -> Posture

`/security/posture`

- KPIs and timelines for ingest/sync,
- score `Safe products / total products`,
- inventory/top breakdown,
- direct navigation to Explorer via `Open Explorer`.

## 7. Security -> Explorer

`/security/explorer`

Scope:

1. `Malware` (overview)
- malware summary table per test,
- drill-down to test details.

2. `Analysis` (`/security/explorer/runs`)
- automatic re-analysis schedule controls,
- run history and requeue failed actions.

3. `Explorer details` (`/security/explorer/tests/:testId`)
- detailed findings table,
- triage status/priority,
- queue/context details,
- `Analysis run history` in expanded finding rows is range-scoped to recent `X` days (default `7d`, selectable near the table).

Permissions:

- triage editing: project `WRITER+`,
- schedule editing: project `ADMIN`.

## 8. Security -> Sources

`/security/sources`

Scope:

- source registry,
- sync full/latest,
- recompute source/summaries,
- sync/recompute history,
- source findings view.

Permissions:

- mutating operations are global `ADMIN` only.

## 9. Security -> Alerts

`/security/alerts`

Scope:

1. `Alert groups`
- deduplicated alert groups,
- acknowledge/close actions,
- `Show in Explorer` for malware groups.

2. `All alerts`
- append-only occurrence stream.

3. `Dedup rules`
- deduplication policy configuration.

4. `Jira routing`
- binding of routing rule to connector profile.

Permissions:

- dedup rules: project `WRITER+`,
- JIRA routing: project `ADMIN`,
- acknowledge/close: project `ADMIN`.

## 10. Settings (global ADMIN)

`/admin/settings/*`

1. `General`
- read-only effective config JSON and metadata.

2. `Connectors`
- connector list,
- connector configuration,
- test connection/send test actions.

3. `Users`
- create/edit/delete users,
- password reset,
- service account token management.

## 11. Events and global search

## Events (`/events`)

- status/severity/category filtering,
- event table,
- open details + acknowledge path.

## Component search (`/search/components`)

- query entered from top bar,
- occurrences results for PURL contains,
- open result in Explorer.

## 12. Account actions

## Change password (`/account/change-password`)

- password update for user accounts,
- service account is blocked from this operation.

## Logout

- available from account menu,
- redirects to `/login`.
