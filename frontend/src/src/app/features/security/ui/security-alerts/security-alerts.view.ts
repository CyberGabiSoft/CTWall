import { AdvancedFilterField, AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import {
  alertGroupExpandedItems,
  alertGroupValue,
  alertOccurrenceExpandedItems,
  alertOccurrenceValue,
} from './security-alerts.mapper';
import { GroupColumnKey, GROUP_COLUMN_KEYS, OCCURRENCE_COLUMN_KEYS, OccurrenceColumnKey } from './security-alerts.tables';
import { isKnownKey } from './security-alerts.utils';
import { sortedOptions } from './security-alerts.utils';

const ALERT_GROUP_STATUS_OPTIONS = ['OPEN', 'CLOSED'] as const;
const DETAIL_COLUMN_PREFIX = '__detail__:';
const NORMALIZED_KEY_PATTERN = /[^a-z0-9]+/g;

type ModeRecord<TKey extends string> = Record<TKey, AdvancedFilterMode>;
type ValueRecord<TKey extends string> = Record<TKey, string>;
type MultiRecord<TKey extends string> = Record<TKey, string[]>;
type OptionsRecord<TKey extends string> = Record<TKey, string[]>;

function normalizeDetailColumnKey(raw: string): string {
  const normalized = (raw ?? '')
    .trim()
    .toLowerCase()
    .replace(NORMALIZED_KEY_PATTERN, '_')
    .replace(/^_+|_+$/g, '');
  if (!normalized) {
    return '';
  }
  return `${DETAIL_COLUMN_PREFIX}${normalized}`;
}

function detailValueByColumnKey(
  columnKey: string,
  items: ReadonlyArray<{ label: string; value: string }>
): string | null {
  if (!columnKey.startsWith(DETAIL_COLUMN_PREFIX)) {
    return null;
  }
  for (const item of items) {
    if (normalizeDetailColumnKey(item.label) !== columnKey) {
      continue;
    }
    const value = (item.value ?? '').trim();
    return value.length > 0 ? item.value : '-';
  }
  return '-';
}

export function groupValueForTable(
  row: AlertGroup,
  key: string,
  groupDetectionDataById?: ReadonlyMap<string, string>
): string {
  if (isKnownKey(key, GROUP_COLUMN_KEYS)) {
    return alertGroupValue(row, key as GroupColumnKey, { groupDetectionDataById });
  }
  return detailValueByColumnKey(
    key,
    alertGroupExpandedItems(row, { groupDetectionDataById })
  ) ?? '-';
}

export function occurrenceValueForTable(row: AlertOccurrence, key: string): string {
  if (isKnownKey(key, OCCURRENCE_COLUMN_KEYS)) {
    return alertOccurrenceValue(row, key as OccurrenceColumnKey);
  }
  return detailValueByColumnKey(key, alertOccurrenceExpandedItems(row)) ?? '-';
}

export function buildGroupFilterOptions(
  rows: AlertGroup[],
  groupDetectionDataById?: ReadonlyMap<string, string>
): OptionsRecord<GroupColumnKey> {
  return {
    severity: sortedOptions(rows.map((row) => alertGroupValue(row, 'severity', { groupDetectionDataById }))),
    status: sortedOptions([
      ...rows.map((row) => alertGroupValue(row, 'status', { groupDetectionDataById })),
      ...ALERT_GROUP_STATUS_OPTIONS
    ]),
    category: sortedOptions(rows.map((row) => alertGroupValue(row, 'category', { groupDetectionDataById }))),
    type: sortedOptions(rows.map((row) => alertGroupValue(row, 'type', { groupDetectionDataById }))),
    detectionMode: sortedOptions(rows.map((row) => alertGroupValue(row, 'detectionMode', { groupDetectionDataById }))),
    detectionData: sortedOptions(rows.map((row) => alertGroupValue(row, 'detectionData', { groupDetectionDataById }))),
    dedupRule: sortedOptions(rows.map((row) => alertGroupValue(row, 'dedupRule', { groupDetectionDataById }))),
    title: sortedOptions(rows.map((row) => alertGroupValue(row, 'title', { groupDetectionDataById }))),
    occurrences: sortedOptions(rows.map((row) => alertGroupValue(row, 'occurrences', { groupDetectionDataById }))),
    firstSeenAt: sortedOptions(rows.map((row) => alertGroupValue(row, 'firstSeenAt', { groupDetectionDataById }))),
    lastSeenAt: sortedOptions(rows.map((row) => alertGroupValue(row, 'lastSeenAt', { groupDetectionDataById }))),
    entityRef: sortedOptions(rows.map((row) => alertGroupValue(row, 'entityRef', { groupDetectionDataById }))),
    id: sortedOptions(rows.map((row) => alertGroupValue(row, 'id', { groupDetectionDataById }))),
  };
}

export function buildOccurrenceFilterOptions(
  rows: AlertOccurrence[]
): OptionsRecord<OccurrenceColumnKey> {
  return {
    severity: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'severity'))),
    category: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'category'))),
    type: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'type'))),
    detectionMode: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'detectionMode'))),
    detectionData: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'detectionData'))),
    title: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'title'))),
    occurredAt: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'occurredAt'))),
    entityRef: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'entityRef'))),
    testId: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'testId'))),
    scopeId: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'scopeId'))),
    productId: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'productId'))),
    groupId: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'groupId'))),
    id: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'id'))),
  };
}

export function buildGroupAdvancedFields(
  mode: ModeRecord<GroupColumnKey>,
  value: ValueRecord<GroupColumnKey>,
  selected: MultiRecord<GroupColumnKey>,
  options: OptionsRecord<GroupColumnKey>
): AdvancedFilterField[] {
  return [
    { key: 'severity', label: 'Severity', mode: mode.severity, value: value.severity, options: options.severity, selected: selected.severity },
    { key: 'status', label: 'Status', mode: mode.status, value: value.status, options: options.status, selected: selected.status },
    { key: 'category', label: 'Category', mode: mode.category, value: value.category, options: options.category, selected: selected.category },
    { key: 'type', label: 'Type', mode: mode.type, value: value.type, options: options.type, selected: selected.type },
    { key: 'detectionMode', label: 'Detection mode', mode: mode.detectionMode, value: value.detectionMode, options: options.detectionMode, selected: selected.detectionMode },
    { key: 'detectionData', label: 'Detection data', mode: mode.detectionData, value: value.detectionData, options: options.detectionData, selected: selected.detectionData },
    { key: 'dedupRule', label: 'Dedup rule', mode: mode.dedupRule, value: value.dedupRule, options: options.dedupRule, selected: selected.dedupRule },
    { key: 'title', label: 'Title', mode: mode.title, value: value.title, options: options.title, selected: selected.title },
    {
      key: 'occurrences',
      label: 'Occurrences',
      mode: mode.occurrences,
      value: value.occurrences,
      options: options.occurrences,
      selected: selected.occurrences
    },
    { key: 'firstSeenAt', label: 'First seen', mode: mode.firstSeenAt, value: value.firstSeenAt, options: options.firstSeenAt, selected: selected.firstSeenAt },
    { key: 'lastSeenAt', label: 'Last seen', mode: mode.lastSeenAt, value: value.lastSeenAt, options: options.lastSeenAt, selected: selected.lastSeenAt },
    { key: 'entityRef', label: 'Entity', mode: mode.entityRef, value: value.entityRef, options: options.entityRef, selected: selected.entityRef },
    { key: 'id', label: 'Group ID', mode: mode.id, value: value.id, options: options.id, selected: selected.id }
  ];
}

export function buildOccurrenceAdvancedFields(
  mode: ModeRecord<OccurrenceColumnKey>,
  value: ValueRecord<OccurrenceColumnKey>,
  selected: MultiRecord<OccurrenceColumnKey>,
  options: OptionsRecord<OccurrenceColumnKey>
): AdvancedFilterField[] {
  return [
    { key: 'severity', label: 'Severity', mode: mode.severity, value: value.severity, options: options.severity, selected: selected.severity },
    { key: 'category', label: 'Category', mode: mode.category, value: value.category, options: options.category, selected: selected.category },
    { key: 'type', label: 'Type', mode: mode.type, value: value.type, options: options.type, selected: selected.type },
    { key: 'detectionMode', label: 'Detection mode', mode: mode.detectionMode, value: value.detectionMode, options: options.detectionMode, selected: selected.detectionMode },
    { key: 'detectionData', label: 'Detection data', mode: mode.detectionData, value: value.detectionData, options: options.detectionData, selected: selected.detectionData },
    { key: 'title', label: 'Title', mode: mode.title, value: value.title, options: options.title, selected: selected.title },
    { key: 'occurredAt', label: 'Occurred', mode: mode.occurredAt, value: value.occurredAt, options: options.occurredAt, selected: selected.occurredAt },
    { key: 'entityRef', label: 'Entity', mode: mode.entityRef, value: value.entityRef, options: options.entityRef, selected: selected.entityRef },
    { key: 'testId', label: 'Test ID', mode: mode.testId, value: value.testId, options: options.testId, selected: selected.testId },
    { key: 'scopeId', label: 'Scope ID', mode: mode.scopeId, value: value.scopeId, options: options.scopeId, selected: selected.scopeId },
    { key: 'productId', label: 'Product ID', mode: mode.productId, value: value.productId, options: options.productId, selected: selected.productId },
    { key: 'groupId', label: 'Group ID', mode: mode.groupId, value: value.groupId, options: options.groupId, selected: selected.groupId },
    { key: 'id', label: 'Occurrence ID', mode: mode.id, value: value.id, options: options.id, selected: selected.id }
  ];
}
