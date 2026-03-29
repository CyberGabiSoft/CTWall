# Feature: Auth

## Scope
Authentication and session handling for GUI users.

## Backend endpoints
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`

## Planned structure
- `auth.store.ts` (Signal-based session state)
- `auth.types.ts` (AuthUser, roles)
- `data-access/` (API calls: login, refresh, me)
- `ui/login/` (login form)
- `ui/logout/` (optional session termination UI)

## Notes
- Use HttpOnly cookies (no JWT in storage).
- 401 handling should trigger refresh once, then redirect to login.
- Login UI lives at `/login` and should be used with a backend config that allows local cookies.
- Login errors must be generic to avoid account enumeration.
