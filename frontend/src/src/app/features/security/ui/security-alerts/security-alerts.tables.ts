import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';

export const ALL_CATEGORIES: string[] = [
  'authn',
  'authz',
  'account',
  'token',
  'config',
  'data_import',
  'data_export',
  'malware',
  'source_sync',
  'api_error',
  'rate_limit',
  'infra_db',
  'infra_storage',
  'infra_external',
  'system'
];

export const GROUP_COLUMN_KEYS = [
  'severity',
  'status',
  'category',
  'type',
  'dedupRule',
  'title',
  'occurrences',
  'firstSeenAt',
  'lastSeenAt',
  'entityRef',
  'id'
] as const;
export type GroupColumnKey = (typeof GROUP_COLUMN_KEYS)[number];

export const OCCURRENCE_COLUMN_KEYS = [
  'severity',
  'category',
  'type',
  'title',
  'occurredAt',
  'entityRef',
  'testId',
  'scopeId',
  'productId',
  'groupId',
  'id'
] as const;
export type OccurrenceColumnKey = (typeof OCCURRENCE_COLUMN_KEYS)[number];

export const GROUP_COLUMNS: ColumnDefinition[] = [
  { key: 'severity', label: 'Severity', sortKey: 'severity', filterKey: 'severity' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
  { key: 'category', label: 'Category', sortKey: 'category', filterKey: 'category' },
  { key: 'type', label: 'Type', sortKey: 'type', filterKey: 'type', className: 'mono' },
  { key: 'dedupRule', label: 'Dedup rule', sortKey: 'dedupRule', filterKey: 'dedupRule' },
  { key: 'title', label: 'Title', sortKey: 'title', filterKey: 'title' },
  { key: 'occurrences', label: 'Active occurrences', sortKey: 'occurrences', filterKey: 'occurrences' },
  { key: 'firstSeenAt', label: 'First seen', sortKey: 'firstSeenAt', filterKey: 'firstSeenAt' },
  { key: 'lastSeenAt', label: 'Last seen', sortKey: 'lastSeenAt', filterKey: 'lastSeenAt' },
  { key: 'entityRef', label: 'Entity', sortKey: 'entityRef', filterKey: 'entityRef', className: 'mono' },
  { key: 'id', label: 'Group ID', sortKey: 'id', filterKey: 'id', className: 'mono' }
];

export const OCCURRENCE_COLUMNS: ColumnDefinition[] = [
  { key: 'severity', label: 'Severity', sortKey: 'severity', filterKey: 'severity' },
  { key: 'category', label: 'Category', sortKey: 'category', filterKey: 'category' },
  { key: 'type', label: 'Type', sortKey: 'type', filterKey: 'type', className: 'mono' },
  { key: 'title', label: 'Title', sortKey: 'title', filterKey: 'title' },
  { key: 'occurredAt', label: 'Occurred', sortKey: 'occurredAt', filterKey: 'occurredAt' },
  { key: 'entityRef', label: 'Entity', sortKey: 'entityRef', filterKey: 'entityRef', className: 'mono' },
  { key: 'testId', label: 'Test ID', sortKey: 'testId', filterKey: 'testId', className: 'mono' },
  { key: 'scopeId', label: 'Scope ID', sortKey: 'scopeId', filterKey: 'scopeId', className: 'mono' },
  { key: 'productId', label: 'Product ID', sortKey: 'productId', filterKey: 'productId', className: 'mono' },
  { key: 'groupId', label: 'Group ID', sortKey: 'groupId', filterKey: 'groupId', className: 'mono' },
  { key: 'id', label: 'Occurrence ID', sortKey: 'id', filterKey: 'id', className: 'mono' }
];
