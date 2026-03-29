# Permissions Model

## 1. Global roles (platform account)

Frontend role definitions:

- `NONE`
- `READER`
- `WRITER`
- `ADMIN`

Role hierarchy (`NONE < READER < WRITER < ADMIN`).

## 2. Project roles (active project context)

Frontend role definitions:

- `NONE`
- `READER`
- `WRITER`
- `ADMIN`

Project roles are bound to the currently selected project in the top bar.

Effective capability model:

- `canRead` -> `READER+`
- `canWrite` -> `WRITER+`
- `canAdmin` -> `ADMIN`

## 3. Global role controls vs project role controls

## 3.1 Global-role controlled

1. Access to admin pages `/admin/projects` and `/admin/settings/*`
- global `ADMIN` only.

2. Visibility of `Settings` submenu and `Manage projects` button
- global `ADMIN` only.

3. Security Sources mutating operations
- edit source,
- enable/disable source,
- sync full/latest,
- recompute source/summaries,
- restricted to global `ADMIN`.

4. Events administrative actions
- acknowledge/administrative actions are tied to global `ADMIN`.

## 3.2 Project-role controlled

1. Data / Browse
- create Product/Scope/Test: `canWrite` (project `WRITER+`),
- delete Product/Scope/Test: `canAdmin` (project `ADMIN`),
- read/list operations: `canRead`.

2. Data / Import
- SBOM upload and submit: `canWrite` (project `WRITER+`).

3. Data / User Groups
- create group: `canWrite`,
- manage group members: `canAdmin` or group owner + `canWrite`.

4. Security / Explorer
- edit triage findings: `canWrite`.

5. Security / Explorer / Analysis (runs)
- edit re-analysis schedule: `canAdmin` (project `ADMIN`).

6. Security / Alerts
- dedup rules: `canWrite`,
- JIRA routing/binding: `canAdmin`,
- acknowledge/close alert group: `canAdmin`.

## 4. Permissions matrix (summary)

| Area / action | READER (project) | WRITER (project) | ADMIN (project) | ADMIN (global) |
|---|---:|---:|---:|---:|
| Dashboard / Posture / Explorer read | Yes | Yes | Yes | Yes |
| Data: create (product/scope/test) | No | Yes | Yes | Yes |
| Data: delete (product/scope/test) | No | No | Yes | Yes |
| Import SBOM | No | Yes | Yes | Yes |
| User Groups: create group | No | Yes | Yes | Yes |
| User Groups: manage members | No | Owner-only* | Yes | Yes |
| Explorer: triage edit | No | Yes | Yes | Yes |
| Explorer Runs: schedule edit | No | No | Yes | Yes |
| Alerts: dedup config | No | Yes | Yes | Yes |
| Alerts: JIRA routing config | No | No | Yes | Yes |
| Security Sources: sync/edit | No | No | No | Yes |
| Admin/Settings + Admin/Projects | No | No | No | Yes |

\* Owner-only: applies to owner of a specific group and still requires project `canWrite`.

## 5. Project-context note

Project permissions are always evaluated for the active project. Switching project:

- updates project role,
- redirects/reloads workspace to `/dashboard`,
- reloads data under the new project scope.

## 6. Account-level notes

- Password change (`/account/change-password`) is available for user accounts.
- Service accounts cannot change passwords (UI hard-block).
