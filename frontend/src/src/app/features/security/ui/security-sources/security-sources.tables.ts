import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';

export const findingsColumnDefinitions: ColumnDefinition[] = [
  { key: 'id', label: 'ID', sortKey: 'id', filterKey: 'id' },
  { key: 'componentPurl', label: 'Component PURL', sortKey: 'componentPurl', filterKey: 'componentPurl' },
  { key: 'isMalware', label: 'Malware', sortKey: 'isMalware', filterKey: 'isMalware' },
  { key: 'resultFilename', label: 'Result file', sortKey: 'resultFilename', filterKey: 'resultFilename' },
  { key: 'detectVersion', label: 'Detect version', sortKey: 'detectVersion', filterKey: 'detectVersion' },
  { key: 'publishedAt', label: 'Published', sortKey: 'publishedAt', filterKey: 'publishedAt' },
  { key: 'modifiedAt', label: 'Modified', sortKey: 'modifiedAt', filterKey: 'modifiedAt' },
  { key: 'createdAt', label: 'Created', sortKey: 'createdAt', filterKey: 'createdAt' },
  { key: 'scanId', label: 'Scan ID', sortKey: 'scanId', filterKey: 'scanId' },
  { key: 'analysisResultId', label: 'Analysis result', sortKey: 'analysisResultId', filterKey: 'analysisResultId' },
  { key: 'componentHash', label: 'Component hash', sortKey: 'componentHash', filterKey: 'componentHash' }
];

export const syncHistoryColumnDefinitions: ColumnDefinition[] = [
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
  { key: 'mode', label: 'Mode', sortKey: 'mode', filterKey: 'mode' },
  { key: 'processed', label: 'Processed', sortKey: 'processed', filterKey: 'processed' },
  { key: 'errors', label: 'Errors', sortKey: 'errors', filterKey: 'errors' },
  { key: 'startedAt', label: 'Started', sortKey: 'startedAt', filterKey: 'startedAt' },
  { key: 'finishedAt', label: 'Finished', sortKey: 'finishedAt', filterKey: 'finishedAt' },
  { key: 'loggedAt', label: 'Logged', sortKey: 'loggedAt', filterKey: 'loggedAt' },
  { key: 'syncId', label: 'Sync ID', sortKey: 'syncId', filterKey: 'syncId' }
];

export const recomputeHistoryColumnDefinitions: ColumnDefinition[] = [
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
  { key: 'affected', label: 'Affected', sortKey: 'affected', filterKey: 'affected' },
  { key: 'enqueued', label: 'Enqueued', sortKey: 'enqueued', filterKey: 'enqueued' },
  { key: 'startedAt', label: 'Started', sortKey: 'startedAt', filterKey: 'startedAt' },
  { key: 'finishedAt', label: 'Finished', sortKey: 'finishedAt', filterKey: 'finishedAt' },
  { key: 'loggedAt', label: 'Logged', sortKey: 'loggedAt', filterKey: 'loggedAt' },
  { key: 'recomputeId', label: 'Recompute ID', sortKey: 'recomputeId', filterKey: 'recomputeId' }
];

export const findingsAdvancedKeys = [
  'componentPurl',
  'resultFilename',
  'detectVersion',
  'isMalware'
] as const;
export const syncHistoryAdvancedKeys = ['status', 'mode', 'syncId'] as const;
export const recomputeHistoryAdvancedKeys = ['status', 'recomputeId'] as const;

export const pageSizes = [10, 25, 50, 100, 0];
export const syncHistoryAutoRefreshIntervalMs = 4000;
export const syncHistoryAutoRefreshStaleMs = 25 * 60 * 1000;
