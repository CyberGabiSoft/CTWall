# Navigation and Sections

## 1. Application structure

The frontend has two main routing contexts:

1. Public page:
- `/login`

2. Authenticated application shell:
- all remaining business sections.

Additionally, selected routes are global-admin-only.

## 2. Top bar (global header)

The top bar contains:

- logo + link to `/dashboard`,
- active project selector,
- manage projects button (visible only for global ADMIN),
- global PURL search (`/search/components`),
- Events button with badge,
- theme switch,
- account menu (change password, logout).

Displayed account name in the top-right corner:

1. `nickname` (if set),
2. otherwise `fullName`,
3. otherwise `email`,
4. fallback: `Account`.

## 3. Left menu - sections and submenus

## Dashboard

- Route: `/dashboard`
- Purpose: quick project health overview (KPIs, top lists, trends, drill-down to Security Explorer/Posture).

## Data

Main menu: `Data`

Submenu:

1. `Browse`
- Route: `/data`
- Purpose: browse and operate on Product/Scope/Test entities (permission-dependent).

2. `Import`
- Route: `/data/import`
- Purpose: upload SBOM and create a new test revision.

3. `Graph`
- Route: `/data/graph`
- Purpose: dependency graph visualization for selected Product/Scope/Test.

4. `User Groups`
- Route: `/data/user-groups`
- Compatibility alias: `/data/identity` -> redirect to `/data/user-groups`
- Purpose: manage groups and memberships in the active project context.

## Security

Main menu: `Security`

Submenu:

1. `Posture`
- Route: `/security/posture`
- Purpose: technical posture (safe products score, KPIs, ingest/sync trends, inventory, failures).

2. `Explorer`
- Base route: `/security/explorer`
- Purpose: malware analysis at test/component level.
- Inside Explorer:
  - `Malware` (overview): `/security/explorer`
  - `Analysis` (runs + schedule): `/security/explorer/runs`
  - Test details: `/security/explorer/tests/:testId`
  - `/security/explorer/config` -> redirect to `/security/explorer/runs`

3. `Sources`
- Route: `/security/sources`
- Purpose: malware intelligence source management and sync/recompute operations.

4. `Alerts`
- Route: `/security/alerts`
- Purpose: alert group and occurrence operations, dedup, JIRA routing.

## Settings (global ADMIN only)

Main menu: `Settings`

Submenu:

1. `General`
- Route: `/admin/settings/general`
- Purpose: read-only effective backend runtime configuration.

2. `Connectors`
- Route: `/admin/settings/connectors`
- Purpose: configure and test global integration connectors.

3. `Users`
- Route: `/admin/settings/users`
- Purpose: manage platform user accounts and global roles.

## 4. Functional routes outside left navigation

- `/events`
  - system events list and filtering.

- `/search/components`
  - global PURL search results.

- `/account/change-password`
  - current account password change.

- `/forbidden`
  - no-permission page.

## 5. Submenu and active-section behavior

Main groups (Data, Security, Settings):

- expand/collapse submenu,
- keep active highlight based on URL (including nested routes),
- auto-expand based on current route.