import {
  AdvancedFilterMode
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { SortDirection } from './admin-settings.tables';

export const createFilterVisibilityDefaults = <T extends string>(keys: readonly T[]): Record<T, boolean> =>
  Object.fromEntries(keys.map((key) => [key, false])) as Record<T, boolean>;

export const createFilterValuesDefaults = <T extends string>(keys: readonly T[]): Record<T, string> =>
  Object.fromEntries(keys.map((key) => [key, ''])) as Record<T, string>;

export const isColumnKey = <T extends string>(value: string, keys: readonly T[]): value is T =>
  (keys as readonly string[]).includes(value);

export const availableColumns = <T extends string>(
  definitions: ColumnDefinition[],
  order: readonly T[]
): ColumnDefinition[] => {
  const selected = new Set(order as readonly string[]);
  return definitions.filter((column) => !selected.has(column.key));
};

export const matchesTextFilter = (value: string, needle: string): boolean => {
  const query = needle.trim().toLowerCase();
  if (!query) {
    return true;
  }
  return value.toLowerCase().includes(query);
};

export const matchesAdvancedFilter = (
  value: string,
  mode: AdvancedFilterMode,
  containsValue: string,
  selectedValues: string[]
): boolean => {
  if (mode === 'select') {
    if (selectedValues.length === 0) {
      return true;
    }
    return selectedValues.includes(value);
  }
  return matchesTextFilter(value, containsValue);
};

export const sortedOptions = (values: string[]): string[] => {
  const unique = new Set<string>();
  values.forEach((value) => {
    const normalized = value.trim();
    if (normalized && normalized !== '-') {
      unique.add(normalized);
    }
  });
  return Array.from(unique).sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' }));
};

export const compareSortValues = (left: string | number, right: string | number): number => {
  if (typeof left === 'number' && typeof right === 'number') {
    return left - right;
  }
  return String(left).localeCompare(String(right), undefined, { sensitivity: 'base' });
};

export const sortRows = <T, TKey extends string>(
  rows: T[],
  sortColumn: TKey | null,
  sortDir: SortDirection,
  valueForSort: (row: T, key: TKey) => string | number
): T[] => {
  if (!sortColumn) {
    return rows;
  }
  const multiplier = sortDir === 'asc' ? 1 : -1;
  return [...rows].sort(
    (left, right) =>
      compareSortValues(valueForSort(left, sortColumn), valueForSort(right, sortColumn)) * multiplier
  );
};

export const timestampValue = (value: string | undefined): number => {
  if (!value) {
    return 0;
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return 0;
  }
  return parsed;
};

export const formatDate = (value: string | undefined): string => {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
};

export const stringifyJson = (value: unknown): string => {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return '{}';
  }
};
