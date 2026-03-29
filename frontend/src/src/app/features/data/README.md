# Feature: Data (Products / Scopes / Tests)

## Scope
Single-view data explorer combining Products, Scopes, and Tests into one UI.

## UX summary
- One page, tabs: Products / Scopes / Tests.
- Table below shows data for the active section.
- Row expands for more details.
- Arrow on the right navigates deeper (Products → Scopes → Tests → Test detail).
- Query field is frontend-only and reflects current selection.
- Data is fetched once and cached in memory.

## Observed fields (backend)
- Products: `id`, `name`, `createdAt`, `updatedAt`
- Scopes: `id`, `productId`, `name`, `createdAt`, `updatedAt` (supports list-all via `GET /api/v1/scopes`)
- Tests: `id`, `scopeId`, `name`, `sbomType.{standard,specVersion}`, `isPublic`, `createdAt`, `updatedAt`
- Tests list-all via `GET /api/v1/tests`
- Revisions: `id`, `testId`, `sbomSha256`, `sbomProducer`, `tags`, `metadataJson`, `sbomMetadataJson`, `componentsImportedCount`, `isActive`, `lastModifiedAt`, `createdAt`
- Components (docelowo): `id`, `revisionId`, `purl`, `pkgName`, `version`, `pkgType`, `pkgNamespace`, `sbomType`, `publisher`, `supplier`, `licenses`, `properties`, `createdAt`

## Related design
See `design_data.md` for full specification.
