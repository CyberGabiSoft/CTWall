# Feature: Ingest (SBOM Upload)

## Scope
Upload SBOM and create/update Product/Scope/Test with a new TestRevision.

## Backend endpoints
- `POST /api/v1/ingest` (multipart upload)

## Planned structure
- `data-access/` (multipart upload helpers)
- `state/` (ingest state and progress)
- `ui/upload/` (upload form and progress UI)

## Notes
- Supports gzip upload and metadata fields (see `DOCS/development/api_endpoints_backend.md`).
- Requires validation and size limits client-side.

## Implemented structure (ctwall)
- `data-access/` (`ingest.api.ts`, `ingest.types.ts`)
- `state/` (`ingest.store.ts`)
- `ui/ingest-shell/` (upload form + drag & drop + progress feedback)

## UX rules
- Upload is enabled only after Product + Scope + Test name are provided and the SBOM file is fully loaded + parsed (JSON validation).
- Manual ingestion accepts SBOM files with any filename extension; payload must still be valid JSON.
- Supported SBOM standards in import flow: `CycloneDX`, `SPDX` (JSON payloads).
- Shows indeterminate progress bar during parse/upload and a green check after completion.
