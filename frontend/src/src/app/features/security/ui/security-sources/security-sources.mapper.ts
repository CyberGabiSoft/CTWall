import { AdvancedFilterField } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { getOwnValue, isSafeObjectKey } from '../../../../shared/utils/safe-object';
import { FilterMode } from '../../../../shared/utils/table-filter-records';
import {
  MalwareSource,
  RecomputeHistoryEntry,
  ScanComponentResult,
  SyncHistoryEntry,
} from '../../data-access/security.types';

export interface SyncHistoryRow {
  id: string;
  status: string;
  statusKind: 'started' | 'complete' | 'failed';
  mode: string;
  processed: string;
  errorsCount: number;
  errorMessage: string;
  startedAt: string;
  finishedAt: string;
  loggedAt: string;
  syncId: string;
}

export interface SyncHistoryDetail {
  label: string;
  value: string;
}

export interface SyncHistoryDetailEntry {
  id: string;
  action: string;
  createdAt: string;
  details: SyncHistoryDetail[];
}

export interface RecomputeHistoryRow {
  id: string;
  status: string;
  statusKind: 'started' | 'complete' | 'failed';
  affected: string;
  enqueued: string;
  startedAt: string;
  finishedAt: string;
  loggedAt: string;
  recomputeId: string;
}

export interface FindingDetail {
  label: string;
  value: string;
}

export interface RecomputeHistoryDetail {
  label: string;
  value: string;
}

export interface RecomputeHistoryDetailEntry {
  id: string;
  action: string;
  createdAt: string;
  details: RecomputeHistoryDetail[];
}

export function syncHistoryActionLabel(action: string): string {
  switch (action) {
    case 'MALWARE_OSV_SYNC_START':
      return 'Sync started';
    case 'MALWARE_OSV_SYNC_COMPLETE':
      return 'Sync completed';
    case 'MALWARE_OSV_SYNC_FAILED':
      return 'Sync failed';
    default:
      return action;
  }
}

export function recomputeHistoryActionLabel(action: string): string {
  switch (action) {
    case 'MALWARE_SOURCE_RESULTS_RECOMPUTE_START':
      return 'Source results recompute started';
    case 'MALWARE_SOURCE_RESULTS_RECOMPUTE_COMPLETE':
      return 'Source results recompute completed';
    case 'MALWARE_SOURCE_RESULTS_RECOMPUTE_FAILED':
      return 'Source results recompute failed';
    case 'MALWARE_SUMMARY_RECOMPUTE_START':
      return 'Summaries recompute started';
    case 'MALWARE_SUMMARY_RECOMPUTE_COMPLETE':
      return 'Summaries recompute completed';
    case 'MALWARE_SUMMARY_RECOMPUTE_FAILED':
      return 'Summaries recompute failed';
    default:
      return action;
  }
}

export function recomputeHistoryStatusClass(row: RecomputeHistoryRow): string {
  switch (row.statusKind) {
    case 'failed':
      return 'status-failed';
    case 'complete':
      return 'status-complete';
    default:
      return 'status-started';
  }
}

export function syncHistoryStatusClass(row: SyncHistoryRow): string {
  switch (row.statusKind) {
    case 'failed':
      return 'status-failed';
    case 'complete':
      return 'status-complete';
    default:
      return 'status-started';
  }
}

export function sourceConfigValue(source: MalwareSource, key: string): string {
  const safeKey = key.trim();
  const config = source.configJson;
  const value =
    config && isSafeObjectKey(safeKey) ? getOwnValue(config as Record<string, unknown>, safeKey) : undefined;
  return typeof value === 'string' && value.trim() ? value : '-';
}

export function findingValue(item: ScanComponentResult, key: string): string {
  switch (key) {
    case 'id':
      return item.id ?? '';
    case 'componentPurl':
      return item.componentPurl ?? '';
    case 'componentHash':
      return item.componentHash ?? '';
    case 'analysisResultId':
      return item.analysisResultId ?? '';
    case 'scanId':
      return item.scanId ?? '';
    case 'resultFilename':
      return item.resultFilename ?? '';
    case 'publishedAt':
      return item.publishedAt ?? '';
    case 'modifiedAt':
      return item.modifiedAt ?? '';
    case 'detectVersion':
      return item.detectVersion ?? '';
    case 'fixedVersion':
      return item.fixedVersion ?? '';
    case 'createdAt':
      return item.createdAt ?? '';
    case 'isMalware':
      return item.isMalware ? 'Yes' : 'No';
    default:
      return '';
  }
}

export function findingDisplayValue(item: ScanComponentResult, key: string): string {
  const value = findingValue(item, key);
  return value.trim() ? value : '-';
}

export function findingsDetailRows(item: ScanComponentResult): FindingDetail[] {
  const keys: Array<{ key: string; label: string }> = [
    { key: 'id', label: 'ID' },
    { key: 'componentPurl', label: 'Component PURL' },
    { key: 'isMalware', label: 'Malware' },
    { key: 'resultFilename', label: 'Result file' },
    { key: 'detectVersion', label: 'Detect version' },
    { key: 'fixedVersion', label: 'Fixed version' },
    { key: 'publishedAt', label: 'Published' },
    { key: 'modifiedAt', label: 'Modified' },
    { key: 'createdAt', label: 'Created' },
    { key: 'scanId', label: 'Scan ID' },
    { key: 'analysisResultId', label: 'Analysis result' },
    { key: 'componentHash', label: 'Component hash' },
  ];

  return keys
    .map(({ key, label }) => ({ label, value: findingDisplayValue(item, key) }))
    .filter((detail) => detail.value !== '-');
}

export function findingsEvidence(item: unknown): string | null {
  if (!isScanComponentResult(item)) {
    return null;
  }
  const evidence = item.evidence?.trim();
  return evidence ? evidence : null;
}

export function findingsDetailsJson(item: unknown): string {
  if (!isScanComponentResult(item)) {
    return '{}';
  }
  const value = item.detailsJson ?? {};
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return '{}';
  }
}

export function recomputeHistoryValue(row: RecomputeHistoryRow, key: string): string {
  switch (key) {
    case 'status':
      return row.status;
    case 'affected':
      return row.affected;
    case 'enqueued':
      return row.enqueued;
    case 'startedAt':
      return row.startedAt;
    case 'finishedAt':
      return row.finishedAt;
    case 'loggedAt':
      return row.loggedAt;
    case 'recomputeId':
      return row.recomputeId;
    default:
      return '';
  }
}

export function syncHistoryValue(row: SyncHistoryRow, key: string): string {
  switch (key) {
    case 'status':
      return row.status;
    case 'mode':
      return row.mode;
    case 'processed':
      return row.processed;
    case 'errors':
      return String(row.errorsCount);
    case 'startedAt':
      return row.startedAt;
    case 'finishedAt':
      return row.finishedAt;
    case 'loggedAt':
      return row.loggedAt;
    case 'syncId':
      return row.syncId;
    default:
      return '';
  }
}

export function buildRecomputeHistoryRows(entries: RecomputeHistoryEntry[]): RecomputeHistoryRow[] {
  const rows = new Map<string, RecomputeHistoryRow>();

  entries.forEach((entry) => {
    const details = extractDetails(entry);
    const recomputeId = recomputeEntryId(entry);
    const existing = rows.get(recomputeId);
    const base: RecomputeHistoryRow =
      existing ??
      {
        id: recomputeId,
        status: 'Started',
        statusKind: 'started',
        affected: '',
        enqueued: '',
        startedAt: '',
        finishedAt: '',
        loggedAt: entry.createdAt,
        recomputeId,
      };

    const next: RecomputeHistoryRow = { ...base };

    const startedAt = detailString(details, 'started_at');
    const finishedAt = detailString(details, 'finished_at');
    const affected = detailString(details, 'affected');
    const enqueued = detailString(details, 'enqueued');

    if (startedAt && (!next.startedAt || startedAt < next.startedAt)) {
      next.startedAt = startedAt;
    } else if (!next.startedAt && entry.action.endsWith('_START')) {
      next.startedAt = entry.createdAt;
    }
    if (finishedAt && (!next.finishedAt || finishedAt > next.finishedAt)) {
      next.finishedAt = finishedAt;
    }
    if (affected) {
      next.affected = affected;
    }
    if (enqueued) {
      next.enqueued = enqueued;
    }

    if (entry.createdAt > next.loggedAt) {
      next.loggedAt = entry.createdAt;
    }

    if (entry.action.endsWith('_FAILED')) {
      next.status = 'Failed';
      next.statusKind = 'failed';
      if (!next.finishedAt) {
        next.finishedAt = entry.createdAt;
      }
    } else if (entry.action.endsWith('_COMPLETE')) {
      if (next.statusKind !== 'failed') {
        next.status = 'Completed';
        next.statusKind = 'complete';
        if (!next.finishedAt) {
          next.finishedAt = entry.createdAt;
        }
      }
    } else if (entry.action.endsWith('_START')) {
      if (next.statusKind === 'started') {
        next.status = 'Running';
      }
    }

    rows.set(recomputeId, next);
  });

  return Array.from(rows.values()).sort((a, b) => b.loggedAt.localeCompare(a.loggedAt));
}

export function buildRecomputeHistoryDetailMap(
  entries: RecomputeHistoryEntry[]
): Map<string, RecomputeHistoryDetailEntry[]> {
  const grouped = new Map<string, RecomputeHistoryDetailEntry[]>();
  entries.forEach((entry) => {
    const recomputeId = recomputeEntryId(entry);
    const details = buildRecomputeHistoryDetails(entry);
    const list = grouped.get(recomputeId) ?? [];
    list.push({ id: entry.id, action: entry.action, createdAt: entry.createdAt, details });
    grouped.set(recomputeId, list);
  });
  grouped.forEach((items) => {
    items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  });
  return grouped;
}

export function buildSyncHistoryRows(entries: SyncHistoryEntry[]): SyncHistoryRow[] {
  const rows = new Map<string, SyncHistoryRow>();
  entries.forEach((entry) => {
    const details = extractDetails(entry);
    const syncId = syncEntryId(entry);
    const existing = rows.get(syncId);
    const base: SyncHistoryRow =
      existing ??
      {
        id: syncId,
        status: 'Started',
        statusKind: 'started',
        mode: '',
        processed: '',
        errorsCount: 0,
        errorMessage: '',
        startedAt: '',
        finishedAt: '',
        loggedAt: entry.createdAt,
        syncId,
      };

    const mode = detailString(details, 'mode');
    const startedAt = detailString(details, 'started_at');
    const finishedAt = detailString(details, 'finished_at');
    const processed = detailString(details, 'processed');
    const errors = detailString(details, 'errors');
    const error = detailString(details, 'error');

    const next: SyncHistoryRow = { ...base };
    const loggedAtBefore = next.loggedAt;

    if (mode) {
      next.mode = mode;
    }
    if (startedAt && (!next.startedAt || startedAt < next.startedAt)) {
      next.startedAt = startedAt;
    } else if (!next.startedAt && entry.action === 'MALWARE_OSV_SYNC_START') {
      next.startedAt = entry.createdAt;
    }
    if (finishedAt && (!next.finishedAt || finishedAt > next.finishedAt)) {
      next.finishedAt = finishedAt;
    }

    if (entry.createdAt > next.loggedAt) {
      next.loggedAt = entry.createdAt;
    }

    // Keep counters from the latest log entry only.
    if (entry.createdAt >= loggedAtBefore) {
      if (processed) {
        next.processed = processed;
      }
      if (errors) {
        const parsed = Number(errors);
        if (Number.isFinite(parsed)) {
          next.errorsCount = parsed;
        }
      }
      if (error) {
        next.errorMessage = error;
      }
    }

    switch (entry.action) {
      case 'MALWARE_OSV_SYNC_FAILED':
        next.status = 'Failed';
        next.statusKind = 'failed';
        if (!next.finishedAt) {
          next.finishedAt = entry.createdAt;
        }
        break;
      case 'MALWARE_OSV_SYNC_PROGRESS':
        if (next.statusKind === 'started') {
          next.status = 'Running';
        }
        break;
      case 'MALWARE_OSV_SYNC_COMPLETE':
        if (next.statusKind !== 'failed') {
          next.status = 'Completed';
          next.statusKind = 'complete';
          if (!next.finishedAt) {
            next.finishedAt = entry.createdAt;
          }
        }
        break;
      case 'MALWARE_OSV_SYNC_START':
        if (!next.statusKind) {
          next.statusKind = 'started';
        }
        break;
      default:
        break;
    }

    rows.set(syncId, next);
  });

  return Array.from(rows.values()).sort((a, b) => b.loggedAt.localeCompare(a.loggedAt));
}

export function buildSyncHistoryDetailMap(
  entries: SyncHistoryEntry[]
): Map<string, SyncHistoryDetailEntry[]> {
  const grouped = new Map<string, SyncHistoryDetailEntry[]>();
  entries.forEach((entry) => {
    const syncId = syncEntryId(entry);
    const details = buildSyncHistoryDetails(entry);
    const list = grouped.get(syncId) ?? [];
    list.push({ id: entry.id, action: entry.action, createdAt: entry.createdAt, details });
    grouped.set(syncId, list);
  });
  grouped.forEach((items) => {
    items.sort((a, b) => b.createdAt.localeCompare(a.createdAt));

    // Keep only latest progress detail plus all non-progress rows.
    const latestProgress = items.find((entry) => entry.action === 'MALWARE_OSV_SYNC_PROGRESS');
    const filtered = items.filter((entry) => entry.action !== 'MALWARE_OSV_SYNC_PROGRESS');
    if (latestProgress) {
      filtered.push(latestProgress);
      filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    }
    items.splice(0, items.length, ...filtered);
  });
  return grouped;
}

export function buildFindingsAdvancedFields(
  modes: Record<string, FilterMode>,
  values: Record<string, string>,
  multi: Record<string, string[]>,
  options: Record<string, string[]>
): AdvancedFilterField[] {
  return [
    {
      key: 'componentPurl',
      label: 'Component PURL',
      mode: modes['componentPurl'],
      value: values['componentPurl'] ?? '',
      options: [],
      selected: multi['componentPurl'] ?? [],
      containsPlaceholder: 'Contains PURL',
    },
    {
      key: 'resultFilename',
      label: 'Result file',
      mode: modes['resultFilename'],
      value: values['resultFilename'] ?? '',
      options: [],
      selected: multi['resultFilename'] ?? [],
      containsPlaceholder: 'Contains filename',
    },
    {
      key: 'detectVersion',
      label: 'Detect version',
      mode: modes['detectVersion'],
      value: values['detectVersion'] ?? '',
      options: options['detectVersion'] ?? [],
      selected: multi['detectVersion'] ?? [],
    },
    {
      key: 'fixedVersion',
      label: 'Fixed version',
      mode: modes['fixedVersion'],
      value: values['fixedVersion'] ?? '',
      options: options['fixedVersion'] ?? [],
      selected: multi['fixedVersion'] ?? [],
    },
    {
      key: 'isMalware',
      label: 'Malware',
      mode: modes['isMalware'],
      value: values['isMalware'] ?? '',
      options: options['isMalware'] ?? [],
      selected: multi['isMalware'] ?? [],
      selectPlaceholder: 'Exact',
    },
  ];
}

export function buildRecomputeHistoryAdvancedFields(
  modes: Record<string, FilterMode>,
  values: Record<string, string>,
  multi: Record<string, string[]>,
  options: Record<string, string[]>
): AdvancedFilterField[] {
  return [
    {
      key: 'status',
      label: 'Status',
      mode: modes['status'],
      value: values['status'] ?? '',
      options: options['status'] ?? [],
      selected: multi['status'] ?? [],
    },
    {
      key: 'recomputeId',
      label: 'Recompute ID',
      mode: modes['recomputeId'],
      value: values['recomputeId'] ?? '',
      options: [],
      selected: [],
      selectPlaceholder: 'Exact',
    },
  ];
}

export function buildSyncHistoryAdvancedFields(
  modes: Record<string, FilterMode>,
  values: Record<string, string>,
  multi: Record<string, string[]>,
  options: Record<string, string[]>
): AdvancedFilterField[] {
  return [
    {
      key: 'status',
      label: 'Status',
      mode: modes['status'],
      value: values['status'] ?? '',
      options: options['status'] ?? [],
      selected: multi['status'] ?? [],
    },
    {
      key: 'mode',
      label: 'Mode',
      mode: modes['mode'],
      value: values['mode'] ?? '',
      options: options['mode'] ?? [],
      selected: multi['mode'] ?? [],
    },
    {
      key: 'syncId',
      label: 'Sync ID',
      mode: modes['syncId'],
      value: values['syncId'] ?? '',
      options: [],
      selected: [],
      selectPlaceholder: 'Exact',
    },
  ];
}

export function isScanComponentResult(value: unknown): value is ScanComponentResult {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record['id'] === 'string' && typeof record['componentPurl'] === 'string';
}

export function isSyncHistoryRow(value: unknown): value is SyncHistoryRow {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const record = value as Record<string, unknown>;
  return typeof record['syncId'] === 'string' && typeof record['errorsCount'] === 'number';
}

function extractDetails(entry: { details?: Record<string, unknown> | undefined }): Record<string, unknown> {
  const details = entry.details;
  if (!details || typeof details !== 'object') {
    return {};
  }
  return details as Record<string, unknown>;
}

function detailString(details: Record<string, unknown>, key: string): string {
  const value = getOwnValue(details, key);
  if (value === null || value === undefined) {
    return '';
  }
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return '';
}

function recomputeEntryId(entry: RecomputeHistoryEntry): string {
  const details = extractDetails(entry);
  return detailString(details, 'recompute_id') || entry.id;
}

function syncEntryId(entry: SyncHistoryEntry): string {
  const details = extractDetails(entry);
  return detailString(details, 'sync_id') || entry.id;
}

function buildRecomputeHistoryDetails(entry: RecomputeHistoryEntry): RecomputeHistoryDetail[] {
  const details = extractDetails(entry);
  const labels: Record<string, string> = {
    reason: 'Reason',
    source_id: 'Source ID',
    recompute_id: 'Recompute ID',
    started_at: 'Started at',
    finished_at: 'Finished at',
    affected: 'Affected',
    enqueued: 'Enqueued',
    error: 'Error',
  };
  const preferredKeys = Object.keys(labels);
  const used = new Set<string>(['recompute_id']);
  const pairs: RecomputeHistoryDetail[] = [];

  preferredKeys.forEach((key) => {
    const value = detailString(details, key);
    if (value) {
      const label = getOwnValue(labels, key);
      pairs.push({ label: typeof label === 'string' ? label : key, value });
      used.add(key);
    }
  });

  if (entry.ipAddress) {
    pairs.push({ label: 'IP address', value: entry.ipAddress });
  }
  if (entry.actorId) {
    pairs.push({ label: 'Actor', value: entry.actorId });
  }
  if (entry.entityId) {
    pairs.push({ label: 'Entity ID', value: entry.entityId });
  }

  Object.keys(details)
    .filter((key) => !used.has(key))
    .sort()
    .forEach((key) => {
      const value = detailString(details, key);
      if (value) {
        pairs.push({ label: key, value });
      }
    });

  return pairs;
}

function buildSyncHistoryDetails(entry: SyncHistoryEntry): SyncHistoryDetail[] {
  const details = extractDetails(entry);
  const labels: Record<string, string> = {
    mode: 'Mode',
    url: 'URL',
    path: 'Path',
    source: 'Source',
    started_at: 'Started at',
    finished_at: 'Finished at',
    processed: 'Processed',
    errors: 'Errors',
    error: 'Error',
  };
  const preferredKeys = Object.keys(labels);
  const used = new Set<string>(['sync_id']);
  const pairs: SyncHistoryDetail[] = [];

  preferredKeys.forEach((key) => {
    const value = detailString(details, key);
    if (value) {
      const label = getOwnValue(labels, key);
      pairs.push({ label: typeof label === 'string' ? label : key, value });
      used.add(key);
    }
  });

  if (entry.ipAddress) {
    pairs.push({ label: 'IP address', value: entry.ipAddress });
  }
  if (entry.actorId) {
    pairs.push({ label: 'Actor', value: entry.actorId });
  }
  if (entry.entityId) {
    pairs.push({ label: 'Entity ID', value: entry.entityId });
  }

  Object.keys(details)
    .filter((key) => !used.has(key))
    .sort()
    .forEach((key) => {
      const value = detailString(details, key);
      if (value) {
        pairs.push({ label: key, value });
      }
    });

  return pairs;
}
