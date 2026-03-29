# API Surface and Domain Sections

## 1. API base and docs

Runtime docs endpoints:

- `GET /docs` (Swagger UI)
- `GET /api/v1/openapi.yaml` (OpenAPI served by backend)

OpenAPI source file:

- `src/backend/api/openapi.yaml`

Health endpoint:

- `GET /health`

## 2. Authentication and account domain

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/change-password`
- `GET /api/v1/auth/me`

## 3. Project/workspace domain

- `GET /api/v1/projects`
- `POST /api/v1/projects`
- `PUT /api/v1/projects/{projectId}`
- `DELETE /api/v1/projects/{projectId}`
- `GET /api/v1/projects/{projectId}/members`
- `PUT /api/v1/projects/{projectId}/members`
- `GET /api/v1/me/project`
- `PUT /api/v1/me/project`

## 4. Dashboard and posture domain

- `GET /api/v1/dashboard/overview`
- `GET /api/v1/security/posture/overview`

## 5. Events and alerts domain

Events:

- `GET /api/v1/events/open-count`
- `GET /api/v1/events`
- `GET /api/v1/events/{eventKey}`
- `POST /api/v1/events/{eventKey}/ack`

Alerts:

- `GET /api/v1/alert-groups`
- `GET /api/v1/alert-groups/{id}`
- `POST /api/v1/alert-groups/{id}/acknowledge`
- `POST /api/v1/alert-groups/{id}/close`
- `GET /api/v1/alert-occurrences`
- `GET /api/v1/alerting/connectors`
- `PUT /api/v1/alerting/connectors/{type}`
- `GET /api/v1/alerting/dedup-rules`
- `PUT /api/v1/alerting/dedup-rules`

## 6. Data domain (products/scopes/tests/revisions)

Products:

- `GET /api/v1/products`
- `POST /api/v1/products`
- `GET /api/v1/products/{productId}`
- `DELETE /api/v1/products/{productId}`
- product access and Jira settings/issues/deliveries endpoints.

Scopes:

- `GET /api/v1/scopes`
- `GET /api/v1/products/{productId}/scopes`
- `POST /api/v1/products/{productId}/scopes`
- `DELETE /api/v1/scopes/{scopeId}`
- scope Jira settings/issues/deliveries endpoints.

Tests and revisions:

- `GET /api/v1/tests`
- `GET /api/v1/scopes/{scopeId}/tests`
- `DELETE /api/v1/tests/{testId}`
- `GET /api/v1/tests/{testId}/revisions`
- revision change/summary endpoints,
- test Jira settings/effective-settings/issues/deliveries endpoints.

Components and search:

- `GET /api/v1/tests/{testId}/components`
- `GET /api/v1/tests/{testId}/components/count`
- `GET /api/v1/tests/{testId}/components/{componentId}`
- `GET /api/v1/search`
- `GET /api/v1/search/component-occurrences`
- graph endpoints under `/api/v1/data/graph/*`.

## 7. Ingest and SBOM domain

- `POST /api/v1/ingest`
- `GET /api/v1/sboms`
- `GET /api/v1/sboms/{revisionId}/download`
- `DELETE /api/v1/sboms/{revisionId}`
- depalert verdict endpoint:
  - `GET /api/v1/tests/{testId}/revisions/{revisionId}/depalert-verdict`

## 8. Security explorer and malware sources domain

Explorer and queues:

- summary, findings, queue, schedule endpoints under:
  - `/api/v1/component-analysis/explorer/*`
  - `/api/v1/tests/{testId}/component-analysis/explorer/*`

Malware sources/results:

- `GET /api/v1/explorer/sources`
- `PATCH /api/v1/explorer/sources/{sourceId}`
- source recompute/sync history endpoints
- aggregated malware results/findings under `/api/v1/explorer/results` and `/api/v1/explorer/findings`.

OSV sync trigger routes (only when OSV service is enabled):

- `POST /api/v1/explorer/osv/download_all`
- `POST /api/v1/explorer/osv/download_latest`

## 9. Groups and users domain

Groups:

- `GET /api/v1/groups`
- `POST /api/v1/groups`
- `GET /api/v1/groups/{groupId}/members`
- `PUT /api/v1/groups/{groupId}/members`

Users:

- `GET /api/v1/users`
- `POST /api/v1/users`
- `PATCH /api/v1/users/{userId}`
- `POST /api/v1/users/{userId}/password`
- `POST /api/v1/users/{userId}/tokens`
- `DELETE /api/v1/users/{userId}`

## 10. Admin settings/connectors domain

- `GET /api/v1/admin/settings/general`
- `GET /api/v1/admin/connectors`
- `PUT /api/v1/admin/connectors/{type}`
- `POST /api/v1/admin/connectors/{type}/test`

## 11. Operational API notes

1. Most list endpoints support pagination (`page`, `pageSize`) and filtering.
2. API errors follow one standardized problem shape.
3. `X-Project-ID` is used where operation is project-scoped.
4. OpenAPI is the source of truth for exact request and response schemas.
