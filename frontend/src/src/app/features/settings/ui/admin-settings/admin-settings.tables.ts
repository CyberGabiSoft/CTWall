import { AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';

export type SortDirection = 'asc' | 'desc';

export const connectorColumnKeys = [
  'type',
  'scopeType',
  'enabled',
  'configured',
  'lastTestStatus',
  'lastTestAt',
  'updatedAt'
] as const;
export type ConnectorColumnKey = (typeof connectorColumnKeys)[number];

export const userColumnKeys = ['id', 'email', 'fullName', 'role', 'accountType', 'createdAt'] as const;
export type UserColumnKey = (typeof userColumnKeys)[number];

export const sourceColumnKeys = ['key', 'source'] as const;
export type SourceColumnKey = (typeof sourceColumnKeys)[number];

export const connectorColumns: ColumnDefinition[] = [
  { key: 'type', label: 'Type', sortKey: 'type', filterKey: 'type' },
  { key: 'scopeType', label: 'Scope', sortKey: 'scopeType', filterKey: 'scopeType' },
  { key: 'enabled', label: 'Enabled', sortKey: 'enabled', filterKey: 'enabled' },
  { key: 'configured', label: 'Configured', sortKey: 'configured', filterKey: 'configured' },
  { key: 'lastTestStatus', label: 'Last test', sortKey: 'lastTestStatus', filterKey: 'lastTestStatus' },
  { key: 'lastTestAt', label: 'Tested at', sortKey: 'lastTestAt', filterKey: 'lastTestAt' },
  { key: 'updatedAt', label: 'Updated', sortKey: 'updatedAt', filterKey: 'updatedAt' }
];

export const userColumns: ColumnDefinition[] = [
  { key: 'id', label: 'User ID', sortKey: 'id', filterKey: 'id' },
  { key: 'email', label: 'Email', sortKey: 'email', filterKey: 'email' },
  { key: 'fullName', label: 'Full name', sortKey: 'fullName', filterKey: 'fullName' },
  { key: 'role', label: 'Role', sortKey: 'role', filterKey: 'role' },
  { key: 'accountType', label: 'Account type', sortKey: 'accountType', filterKey: 'accountType' },
  { key: 'createdAt', label: 'Created', sortKey: 'createdAt', filterKey: 'createdAt' }
];

export const sourceColumns: ColumnDefinition[] = [
  { key: 'key', label: 'Key', sortKey: 'key', filterKey: 'key' },
  { key: 'source', label: 'Source', sortKey: 'source', filterKey: 'source' }
];

export const createConnectorFilterMode = (): Record<ConnectorColumnKey, AdvancedFilterMode> => ({
  type: 'contains',
  scopeType: 'contains',
  enabled: 'contains',
  configured: 'contains',
  lastTestStatus: 'contains',
  lastTestAt: 'contains',
  updatedAt: 'contains'
});

export const createConnectorMultiFilters = (): Record<ConnectorColumnKey, string[]> => ({
  type: [],
  scopeType: [],
  enabled: [],
  configured: [],
  lastTestStatus: [],
  lastTestAt: [],
  updatedAt: []
});

export const createUserFilterMode = (): Record<UserColumnKey, AdvancedFilterMode> => ({
  id: 'contains',
  email: 'contains',
  fullName: 'contains',
  role: 'contains',
  accountType: 'contains',
  createdAt: 'contains'
});

export const createUserMultiFilters = (): Record<UserColumnKey, string[]> => ({
  id: [],
  email: [],
  fullName: [],
  role: [],
  accountType: [],
  createdAt: []
});

export const createSourceFilterMode = (): Record<SourceColumnKey, AdvancedFilterMode> => ({
  key: 'contains',
  source: 'contains'
});

export const createSourceMultiFilters = (): Record<SourceColumnKey, string[]> => ({
  key: [],
  source: []
});
