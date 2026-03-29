import { AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import { GroupColumnKey, OccurrenceColumnKey } from './security-alerts.tables';
import { SortDirection } from './security-alerts.table-state';
import {
  formatDate,
  groupDedupRule,
  groupDedupeKeys,
  groupKeyPart,
  matchesAdvancedFilter,
} from './security-alerts.utils';

export interface ExpandedDetailItem {
  label: string;
  value: string;
  mono?: boolean;
  copyValue?: string;
}

export interface AlertGroupFilterState {
  filters: Record<GroupColumnKey, string>;
  modes: Record<GroupColumnKey, AdvancedFilterMode>;
  selected: Record<GroupColumnKey, string[]>;
  sortColumn: GroupColumnKey | null;
  sortDirection: SortDirection;
}

export interface AlertOccurrenceFilterState {
  filters: Record<OccurrenceColumnKey, string>;
  modes: Record<OccurrenceColumnKey, AdvancedFilterMode>;
  selected: Record<OccurrenceColumnKey, string[]>;
  sortColumn: OccurrenceColumnKey | null;
  sortDirection: SortDirection;
}

export function alertGroupValue(row: AlertGroup, key: GroupColumnKey): string {
  switch (key) {
    case 'severity':
      return row.severity ?? '-';
    case 'status':
      return row.status ?? '-';
    case 'category':
      return row.category ?? '-';
    case 'type':
      return row.type ?? '-';
    case 'dedupRule':
      return groupDedupRule(row.groupKey);
    case 'title':
      return row.title ?? '-';
    case 'occurrences':
      return String(row.occurrences ?? 0);
    case 'firstSeenAt':
      return formatDate(row.firstSeenAt);
    case 'lastSeenAt':
      return formatDate(row.lastSeenAt);
    case 'entityRef':
      return row.entityRef ?? '-';
    case 'id':
      return row.id ?? '-';
    default:
      return '-';
  }
}

export function alertOccurrenceValue(row: AlertOccurrence, key: OccurrenceColumnKey): string {
  switch (key) {
    case 'severity':
      return row.severity ?? '-';
    case 'category':
      return row.category ?? '-';
    case 'type':
      return row.type ?? '-';
    case 'title':
      return row.title ?? '-';
    case 'occurredAt':
      return formatDate(row.occurredAt);
    case 'entityRef':
      return row.entityRef ?? '-';
    case 'testId':
      return row.testId ?? '-';
    case 'scopeId':
      return row.scopeId ?? '-';
    case 'productId':
      return row.productId ?? '-';
    case 'groupId':
      return row.groupId ?? '-';
    case 'id':
      return row.id ?? '-';
    default:
      return '-';
  }
}

export function isMalwareAlertGroup(row: AlertGroup): boolean {
  return (row.category ?? '').toLowerCase() === 'malware' || (row.type ?? '') === 'malware.detected';
}

export function isMalwareAlertOccurrence(row: AlertOccurrence): boolean {
  return (row.category ?? '').toLowerCase() === 'malware' || (row.type ?? '') === 'malware.detected';
}

export function alertSeverityClass(severity: string | null | undefined): string {
  const normalized = (severity ?? '').toUpperCase();
  if (normalized === 'ERROR') return 'severity-pill severity-pill--error';
  if (normalized === 'WARN') return 'severity-pill severity-pill--warn';
  if (normalized === 'INFO') return 'severity-pill severity-pill--info';
  return 'severity-pill';
}

export function alertStatusClass(status: string | null | undefined): string {
  const normalized = (status ?? '').toUpperCase();
  if (normalized === 'OPEN') return 'status-pill status-pill--open';
  if (normalized === 'ACKNOWLEDGED') return 'status-pill status-pill--ack';
  if (normalized === 'CLOSED') return 'status-pill status-pill--closed';
  return 'status-pill';
}

export function acknowledgeActionTooltip(row: AlertGroup, isAdmin: boolean): string {
  if (isMalwareAlertGroup(row)) {
    return 'Managed in Explorer';
  }
  if (!isAdmin) {
    return 'Admin only';
  }
  return 'Acknowledge';
}

export function closeActionTooltip(row: AlertGroup, isAdmin: boolean): string {
  if (isMalwareAlertGroup(row)) {
    return 'Managed in Explorer';
  }
  if (!isAdmin) {
    return 'Admin only';
  }
  return 'Close';
}

export function alertGroupExpandedItems(row: AlertGroup): ExpandedDetailItem[] {
  const malwarePurl = groupKeyPart(row.groupKey, 'malware_purl');
  return [
    { label: 'Group ID', value: row.id ?? '-', mono: true },
    { label: 'Dedup rule', value: groupDedupRule(row.groupKey) },
    { label: 'Dedupe keys', value: groupDedupeKeys(row.groupKey), mono: true },
    { label: 'Group key', value: row.groupKey ?? '-', mono: true },
    { label: 'Status', value: row.status ?? '-' },
    { label: 'Severity', value: row.severity ?? '-' },
    { label: 'Category', value: row.category ?? '-' },
    { label: 'Type', value: row.type ?? '-', mono: true },
    { label: 'Malware PURL', value: malwarePurl || '-', mono: true },
    { label: 'First seen', value: formatDate(row.firstSeenAt) },
    { label: 'Last seen', value: formatDate(row.lastSeenAt) },
    { label: 'Last notified', value: formatDate(row.lastNotifiedAt ?? null) },
    { label: 'Acknowledged at', value: formatDate(row.acknowledgedAt ?? null) },
    { label: 'Acknowledged by', value: row.acknowledgedBy ?? '-', mono: true },
    { label: 'Closed at', value: formatDate(row.closedAt ?? null) },
    { label: 'Closed by', value: row.closedBy ?? '-', mono: true },
  ];
}

export function alertOccurrenceExpandedItems(row: AlertOccurrence): ExpandedDetailItem[] {
  return [
    { label: 'Occurrence ID', value: row.id ?? '-', mono: true },
    { label: 'Group ID', value: row.groupId ?? '-', mono: true },
    { label: 'Severity', value: row.severity ?? '-' },
    { label: 'Category', value: row.category ?? '-' },
    { label: 'Type', value: row.type ?? '-', mono: true },
    { label: 'Title', value: row.title ?? '-' },
    { label: 'Occurred', value: formatDate(row.occurredAt) },
    { label: 'Entity', value: row.entityRef ?? '-', mono: true },
    { label: 'Product ID', value: row.productId ?? '-', mono: true },
    { label: 'Scope ID', value: row.scopeId ?? '-', mono: true },
    { label: 'Test ID', value: row.testId ?? '-', mono: true },
  ];
}

export function alertOccurrenceDetailsJson(row: AlertOccurrence): string {
  try {
    return JSON.stringify(row.details ?? {}, null, 2);
  } catch {
    return '{}';
  }
}

export function applyGroupFiltersAndSort(
  items: AlertGroup[],
  state: AlertGroupFilterState
): AlertGroup[] {
  const filtered = items.filter((row) => {
    if (!matchesAdvancedFilter(alertGroupValue(row, 'severity'), state.modes.severity, state.filters.severity, state.selected.severity)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'status'), state.modes.status, state.filters.status, state.selected.status)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'category'), state.modes.category, state.filters.category, state.selected.category)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'type'), state.modes.type, state.filters.type, state.selected.type)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'dedupRule'), state.modes.dedupRule, state.filters.dedupRule, state.selected.dedupRule)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'title'), state.modes.title, state.filters.title, state.selected.title)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'occurrences'), state.modes.occurrences, state.filters.occurrences, state.selected.occurrences)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'firstSeenAt'), state.modes.firstSeenAt, state.filters.firstSeenAt, state.selected.firstSeenAt)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'lastSeenAt'), state.modes.lastSeenAt, state.filters.lastSeenAt, state.selected.lastSeenAt)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'entityRef'), state.modes.entityRef, state.filters.entityRef, state.selected.entityRef)) return false;
    if (!matchesAdvancedFilter(alertGroupValue(row, 'id'), state.modes.id, state.filters.id, state.selected.id)) return false;
    return true;
  });
  return sortGroups(filtered, state.sortColumn, state.sortDirection);
}

export function applyOccurrenceFiltersAndSort(
  items: AlertOccurrence[],
  state: AlertOccurrenceFilterState
): AlertOccurrence[] {
  const filtered = items.filter((row) => {
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'severity'), state.modes.severity, state.filters.severity, state.selected.severity)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'category'), state.modes.category, state.filters.category, state.selected.category)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'type'), state.modes.type, state.filters.type, state.selected.type)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'title'), state.modes.title, state.filters.title, state.selected.title)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'occurredAt'), state.modes.occurredAt, state.filters.occurredAt, state.selected.occurredAt)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'entityRef'), state.modes.entityRef, state.filters.entityRef, state.selected.entityRef)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'testId'), state.modes.testId, state.filters.testId, state.selected.testId)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'scopeId'), state.modes.scopeId, state.filters.scopeId, state.selected.scopeId)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'productId'), state.modes.productId, state.filters.productId, state.selected.productId)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'groupId'), state.modes.groupId, state.filters.groupId, state.selected.groupId)) return false;
    if (!matchesAdvancedFilter(alertOccurrenceValue(row, 'id'), state.modes.id, state.filters.id, state.selected.id)) return false;
    return true;
  });
  return sortOccurrences(filtered, state.sortColumn, state.sortDirection);
}

function sortGroups(
  items: AlertGroup[],
  sortColumn: GroupColumnKey | null,
  sortDirection: SortDirection
): AlertGroup[] {
  if (!sortColumn) {
    return items;
  }
  const directionMultiplier = sortDirection === 'asc' ? 1 : -1;
  return [...items].sort((left, right) => {
    if (sortColumn === 'occurrences') {
      return ((left.occurrences ?? 0) - (right.occurrences ?? 0)) * directionMultiplier;
    }
    if (sortColumn === 'firstSeenAt') {
      return (Date.parse(left.firstSeenAt ?? '') - Date.parse(right.firstSeenAt ?? '')) * directionMultiplier;
    }
    if (sortColumn === 'lastSeenAt') {
      return (
        Date.parse(left.lastSeenAt ?? '') - (Date.parse(right.lastSeenAt ?? '') || 0)
      ) * directionMultiplier;
    }
    return (
      alertGroupValue(left, sortColumn).localeCompare(alertGroupValue(right, sortColumn), undefined, {
        sensitivity: 'base',
      }) * directionMultiplier
    );
  });
}

function sortOccurrences(
  items: AlertOccurrence[],
  sortColumn: OccurrenceColumnKey | null,
  sortDirection: SortDirection
): AlertOccurrence[] {
  if (!sortColumn) {
    return items;
  }
  const directionMultiplier = sortDirection === 'asc' ? 1 : -1;
  return [...items].sort((left, right) => {
    if (sortColumn === 'occurredAt') {
      return (Date.parse(left.occurredAt ?? '') - Date.parse(right.occurredAt ?? '')) * directionMultiplier;
    }
    return (
      alertOccurrenceValue(left, sortColumn).localeCompare(
        alertOccurrenceValue(right, sortColumn),
        undefined,
        { sensitivity: 'base' }
      ) * directionMultiplier
    );
  });
}
