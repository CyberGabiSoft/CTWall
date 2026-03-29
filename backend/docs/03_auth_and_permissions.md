# Authentication and Permissions

## 1. Global roles

Backend global account roles:

- `ADMIN`
- `WRITER`
- `READER`
- `NONE`

Global role controls access to platform-wide areas (for example admin settings).

## 2. Account types

Supported account types:

- `USER`
- `SERVICE_ACCOUNT`

Important behavior:

- user account: interactive UI login and account operations,
- service account: automation/integration usage via API credentials.

## 3. Authentication methods

## 3.1 Session login

Primary browser flow:

- sign in with user credentials,
- receive session/refresh cookies,
- use refresh endpoint to keep session active.

## 3.2 API token (Bearer)

Alternative API flow:

- `Authorization: Bearer <token>`,
- used mainly by CI/CD and service integrations.

## 4. Request integrity behavior

For state-changing requests in browser session mode:

- client sends anti-CSRF token together with request.

Token-authenticated automation requests do not use browser CSRF flow.

## 5. Project context resolution

Backend resolves active project in this order:

1. `X-Project-ID` header (if present and accessible),
2. persisted selected project in user settings,
3. first accessible project fallback.

Selected project is persisted server-side for next requests.

## 6. Project-level roles

Project role values:

- `ADMIN`
- `WRITER`
- `READER`

Role hierarchy:

- `ADMIN > WRITER > READER`

Each project-scoped endpoint enforces minimum required project role.

## 7. Entity-specific authorization rules (examples)

1. Global-admin-only routes:
- admin settings/users/projects management,
- selected security source mutation endpoints,
- selected schedule mutation endpoints.

2. Project-admin constraints:
- selected alerting/Jira settings mutations,
- selected product/test governance operations.

3. Additional ownership rules:
- selected Jira settings operations can depend on ownership and project role together.

## 8. Authorization failure visibility

Denied authentication or authorization operations are recorded as system events and can be reviewed in Events/Alerts views.
