import { AdvancedFilterField, AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import { alertGroupValue, alertOccurrenceValue } from './security-alerts.mapper';
import { GroupColumnKey, GROUP_COLUMN_KEYS, OCCURRENCE_COLUMN_KEYS, OccurrenceColumnKey } from './security-alerts.tables';
import { isKnownKey } from './security-alerts.utils';
import { sortedOptions } from './security-alerts.utils';

type ModeRecord<TKey extends string> = Record<TKey, AdvancedFilterMode>;
type ValueRecord<TKey extends string> = Record<TKey, string>;
type MultiRecord<TKey extends string> = Record<TKey, string[]>;
type OptionsRecord<TKey extends string> = Record<TKey, string[]>;

export function groupValueForTable(row: AlertGroup, key: string): string {
  if (!isKnownKey(key, GROUP_COLUMN_KEYS)) {
    return '-';
  }
  return alertGroupValue(row, key as GroupColumnKey);
}

export function occurrenceValueForTable(row: AlertOccurrence, key: string): string {
  if (!isKnownKey(key, OCCURRENCE_COLUMN_KEYS)) {
    return '-';
  }
  return alertOccurrenceValue(row, key as OccurrenceColumnKey);
}

export function buildGroupFilterOptions(rows: AlertGroup[]): OptionsRecord<GroupColumnKey> {
  return {
    severity: sortedOptions(rows.map((row) => alertGroupValue(row, 'severity'))),
    status: sortedOptions(rows.map((row) => alertGroupValue(row, 'status'))),
    category: sortedOptions(rows.map((row) => alertGroupValue(row, 'category'))),
    type: sortedOptions(rows.map((row) => alertGroupValue(row, 'type'))),
    dedupRule: sortedOptions(rows.map((row) => alertGroupValue(row, 'dedupRule'))),
    title: sortedOptions(rows.map((row) => alertGroupValue(row, 'title'))),
    occurrences: sortedOptions(rows.map((row) => alertGroupValue(row, 'occurrences'))),
    firstSeenAt: sortedOptions(rows.map((row) => alertGroupValue(row, 'firstSeenAt'))),
    lastSeenAt: sortedOptions(rows.map((row) => alertGroupValue(row, 'lastSeenAt'))),
    entityRef: sortedOptions(rows.map((row) => alertGroupValue(row, 'entityRef'))),
    id: sortedOptions(rows.map((row) => alertGroupValue(row, 'id'))),
  };
}

export function buildOccurrenceFilterOptions(
  rows: AlertOccurrence[]
): OptionsRecord<OccurrenceColumnKey> {
  return {
    severity: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'severity'))),
    category: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'category'))),
    type: sortedOptions(rows.map((row) => alertOccurrenceValue(row, 'type'))),
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
