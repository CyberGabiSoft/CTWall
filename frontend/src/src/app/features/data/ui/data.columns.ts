import type { ColumnDefinition } from '../../../shared/ui/data-table/data-table.types';

export type { ColumnDefinition };

export type ProductColumnKey = 'name' | 'scopes' | 'updated';
export type ScopeColumnKey = 'name' | 'tests' | 'updated';
export type TestColumnKey = 'name' | 'id' | 'components' | 'updated';
export type RevisionColumnKey =
  | 'revision'
  | 'sbomSha'
  | 'producer'
  | 'tags'
  | 'components'
  | 'active'
  | 'lastModified';

export type LastChangeColumnKey =
  | 'toRevision'
  | 'fromRevision'
  | 'status'
  | 'added'
  | 'removed'
  | 'reappeared'
  | 'unchanged'
  | 'computedAt'
  | 'createdAt';

export type RevisionChangeColumnKey =
  | 'diffType'
  | 'findingType'
  | 'componentPurl'
  | 'malwarePurl'
  | 'createdAt';

export type ComponentColumnKey =
  | 'purl'
  | 'pkgType'
  | 'pkgName'
  | 'version'
  | 'pkgNamespace'
  | 'licenses'
  | 'sbomType'
  | 'publisher'
  | 'supplier'
  | 'malwareVerdict'
  | 'malwareScannedAt'
  | 'malwareValidUntil';

export type ComponentColumnFilterKey =
  | 'purl'
  | 'type'
  | 'name'
  | 'version'
  | 'namespace'
  | 'licenses'
  | 'sbomType'
  | 'publisher'
  | 'supplier'
  | 'malwareVerdict'
  | 'malwareScannedAt'
  | 'malwareValidUntil';

export const PRODUCT_COLUMNS: ColumnDefinition<ProductColumnKey>[] = [
  { key: 'name', label: 'Name', sortKey: 'name', filterKey: 'name', className: 'col-name' },
  { key: 'scopes', label: 'Scopes', sortKey: 'scopes', filterKey: 'scopes', className: 'col-scopes' },
  { key: 'updated', label: 'Updated', sortKey: 'updated', filterKey: 'updated', className: 'col-updated' }
];

export const SCOPE_COLUMNS: ColumnDefinition<ScopeColumnKey>[] = [
  { key: 'name', label: 'Name', sortKey: 'name', filterKey: 'name', className: 'col-name' },
  { key: 'tests', label: 'Tests', sortKey: 'tests', filterKey: 'tests', className: 'col-tests' },
  { key: 'updated', label: 'Updated', sortKey: 'updated', filterKey: 'updated', className: 'col-updated' }
];

export const TEST_COLUMNS: ColumnDefinition<TestColumnKey>[] = [
  { key: 'name', label: 'Name', sortKey: 'name', filterKey: 'name', className: 'col-name' },
  { key: 'id', label: 'ID', sortKey: 'id', filterKey: 'id', className: 'mono col-id' },
  {
    key: 'components',
    label: 'Components',
    sortKey: 'components',
    filterKey: 'components',
    className: 'col-components'
  },
  { key: 'updated', label: 'Updated', sortKey: 'updated', filterKey: 'updated', className: 'col-updated' }
];

export const REVISION_COLUMNS: ColumnDefinition<RevisionColumnKey>[] = [
  { key: 'revision', label: 'Revision', sortKey: 'revision', filterKey: 'revision', className: 'mono col-revision' },
  { key: 'sbomSha', label: 'SBOM SHA', sortKey: 'sbomSha', filterKey: 'sbomSha', className: 'mono col-sbom-sha' },
  { key: 'producer', label: 'Producer', sortKey: 'producer', filterKey: 'producer', className: 'col-producer' },
  { key: 'tags', label: 'Tags', sortKey: 'tags', filterKey: 'tags', className: 'col-tags' },
  {
    key: 'components',
    label: 'Components',
    sortKey: 'components',
    filterKey: 'components',
    className: 'col-components'
  },
  { key: 'active', label: 'Active', sortKey: 'active', filterKey: 'active', className: 'col-active' },
  {
    key: 'lastModified',
    label: 'Last modified',
    sortKey: 'lastModified',
    filterKey: 'lastModified',
    className: 'col-last-modified'
  }
];

export const LAST_CHANGE_COLUMNS: ColumnDefinition<LastChangeColumnKey>[] = [
  { key: 'toRevision', label: 'To revision', sortKey: 'toRevision', filterKey: 'toRevision', className: 'mono col-revision' },
  { key: 'fromRevision', label: 'From revision', sortKey: 'fromRevision', filterKey: 'fromRevision', className: 'mono col-revision' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status', className: 'col-status' },
  { key: 'added', label: 'Added', sortKey: 'added', filterKey: 'added', className: 'col-count' },
  { key: 'removed', label: 'Removed', sortKey: 'removed', filterKey: 'removed', className: 'col-count' },
  { key: 'reappeared', label: 'Reappeared', sortKey: 'reappeared', filterKey: 'reappeared', className: 'col-count' },
  { key: 'unchanged', label: 'Unchanged', sortKey: 'unchanged', filterKey: 'unchanged', className: 'col-count' },
  { key: 'computedAt', label: 'Computed at', sortKey: 'computedAt', filterKey: 'computedAt', className: 'col-updated' },
  { key: 'createdAt', label: 'Created at', sortKey: 'createdAt', filterKey: 'createdAt', className: 'col-updated' }
];

export const REVISION_CHANGE_COLUMNS: ColumnDefinition<RevisionChangeColumnKey>[] = [
  { key: 'diffType', label: 'Diff type', sortKey: 'diffType', filterKey: 'diffType', className: 'col-status' },
  { key: 'findingType', label: 'Finding type', sortKey: 'findingType', filterKey: 'findingType', className: 'col-type' },
  { key: 'componentPurl', label: 'Component PURL', sortKey: 'componentPurl', filterKey: 'componentPurl', className: 'mono col-purl' },
  { key: 'malwarePurl', label: 'Malware PURL', sortKey: 'malwarePurl', filterKey: 'malwarePurl', className: 'mono col-purl' },
  { key: 'createdAt', label: 'Created at', sortKey: 'createdAt', filterKey: 'createdAt', className: 'col-updated' }
];

export const COMPONENT_COLUMNS: ColumnDefinition<ComponentColumnKey, ComponentColumnFilterKey>[] = [
  { key: 'purl', label: 'PURL', sortKey: 'purl', filterKey: 'purl', className: 'col-purl' },
  { key: 'pkgType', label: 'Pkg Type', sortKey: 'pkgType', filterKey: 'type', className: 'col-type' },
  { key: 'pkgName', label: 'Pkg Name', sortKey: 'pkgName', filterKey: 'name', className: 'col-name' },
  { key: 'version', label: 'Version', sortKey: 'version', filterKey: 'version', className: 'col-version' },
  {
    key: 'pkgNamespace',
    label: 'Pkg Namespace',
    sortKey: 'pkgNamespace',
    filterKey: 'namespace',
    className: 'col-namespace'
  },
  { key: 'licenses', label: 'Licenses', sortKey: 'licenses', filterKey: 'licenses', className: 'col-licenses' },
  {
    key: 'sbomType',
    label: 'SBOM Type',
    sortKey: 'sbomType',
    filterKey: 'sbomType',
    className: 'col-sbom-type'
  },
  {
    key: 'publisher',
    label: 'Publisher',
    sortKey: 'publisher',
    filterKey: 'publisher',
    className: 'col-publisher'
  },
  {
    key: 'supplier',
    label: 'Supplier',
    sortKey: 'supplier',
    filterKey: 'supplier',
    className: 'col-supplier'
  },
  {
    key: 'malwareVerdict',
    label: 'Malware verdict',
    sortKey: 'malwareVerdict',
    filterKey: 'malwareVerdict',
    className: 'col-malware'
  },
  {
    key: 'malwareScannedAt',
    label: 'Last scanned',
    sortKey: 'malwareScannedAt',
    filterKey: 'malwareScannedAt',
    className: 'col-malware-scanned'
  },
  {
    key: 'malwareValidUntil',
    label: 'Valid until',
    sortKey: 'malwareValidUntil',
    filterKey: 'malwareValidUntil',
    className: 'col-malware-valid'
  }
];

export const COMPONENT_DEFAULT_COLUMNS: ComponentColumnKey[] = [
  'purl',
  'pkgType',
  'pkgName',
  'version',
  'pkgNamespace',
  'malwareVerdict',
  'malwareScannedAt',
  'malwareValidUntil'
];
