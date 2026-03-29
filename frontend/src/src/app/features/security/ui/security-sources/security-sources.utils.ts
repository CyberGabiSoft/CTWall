import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { DataTableExpandedDetailItem } from '../../../../shared/ui/data-table/data-table-expanded-details.component';
import { defineOwnValue, getOwnValue, isSafeObjectKey } from '../../../../shared/utils/safe-object';
import { FilterMode } from '../../../../shared/utils/table-filter-records';

export type SortDirection = 'asc' | 'desc';

export const toExpandedDetails = (
  details: readonly { label: string; value: string }[]
): DataTableExpandedDetailItem[] =>
  details.map((detail) => ({
    label: detail.label,
    value: detail.value,
    copyValue: detail.value
  }));

export const buildFilterOptions = <T>(
  items: T[],
  keys: readonly string[],
  valueForKey: (item: T, key: string) => string
): Record<string, string[]> => {
  const options: Record<string, string[]> = {};
  keys.forEach((key) => {
    if (!isSafeObjectKey(key)) {
      return;
    }
    const values = new Set<string>();
    items.forEach((item) => {
      const value = valueForKey(item, key).trim();
      if (value && value !== '-') {
        values.add(value);
      }
    });
    defineOwnValue(options, key, Array.from(values).sort((a, b) => a.localeCompare(b)));
  });
  return options;
};

export const applySelectFilters = <T>(
  items: T[],
  modes: Record<string, FilterMode>,
  multiFilters: Record<string, string[]>,
  valueForKey: (item: T, key: string) => string
): T[] => {
  const entries = Object.entries(modes).filter(([, mode]) => mode === 'select');
  if (entries.length === 0) {
    return items;
  }
  return items.filter((item) =>
    entries.every(([key]) => {
      const selectedValue = getOwnValue(multiFilters, key);
      const selected = Array.isArray(selectedValue) ? selectedValue.filter((entry) => typeof entry === 'string') : [];
      if (selected.length === 0) {
        return true;
      }
      const value = valueForKey(item, key);
      return selected.includes(value);
    })
  );
};

export const resetFiltersForSelectModes = (
  filters: Record<string, string>,
  modes: Record<string, FilterMode>
): Record<string, string> => {
  const next: Record<string, string> = { ...filters };
  Object.entries(modes).forEach(([key, mode]) => {
    if (mode === 'select') {
      if (!isSafeObjectKey(key)) {
        return;
      }
      defineOwnValue(next, key, '');
    }
  });
  return next;
};

export const setFilterValueFromString = (
  filters: Record<string, string>,
  key: string,
  value: string
): Record<string, string> => {
  const next: Record<string, string> = { ...filters };
  if (!isSafeObjectKey(key)) {
    return next;
  }
  defineOwnValue(next, key, value);
  return next;
};

export const applyGlobalFilter = <T>(
  items: T[],
  filter: string,
  definitions: ColumnDefinition[],
  valueForKey: (item: T, key: string) => string
): T[] => {
  if (!filter) {
    return items;
  }
  const keys = definitions.map((column) => column.key);
  return items.filter((item) => keys.some((key) => valueForKey(item, key).toLowerCase().includes(filter)));
};

export const applyColumnFilters = <T>(
  items: T[],
  filters: Record<string, string>,
  valueForKey: (item: T, key: string) => string
): T[] => {
  const active = Object.entries(filters).filter(([, value]) => value.trim().length > 0);
  if (active.length === 0) {
    return items;
  }
  return items.filter((item) =>
    active.every(([key, value]) => valueForKey(item, key).toLowerCase().includes(value.trim().toLowerCase()))
  );
};

export const applySort = <T>(
  items: T[],
  column: string,
  dir: SortDirection,
  valueForKey: (item: T, key: string) => string
): T[] => {
  const sorted = [...items].sort((a, b) => {
    const left = normalizeSortValue(valueForKey(a, column));
    const right = normalizeSortValue(valueForKey(b, column));
    return compareValues(left, right);
  });
  return dir === 'desc' ? sorted.reverse() : sorted;
};

const normalizeSortValue = (value: string): string => {
  const trimmed = value.trim();
  return trimmed === '-' ? '' : trimmed;
};

const compareValues = (left: string, right: string): number => {
  if (left === '' && right === '') {
    return 0;
  }
  if (left === '') {
    return 1;
  }
  if (right === '') {
    return -1;
  }
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (!Number.isNaN(leftNumber) && !Number.isNaN(rightNumber)) {
    return leftNumber - rightNumber;
  }
  const leftDate = Date.parse(left);
  const rightDate = Date.parse(right);
  if (!Number.isNaN(leftDate) && !Number.isNaN(rightDate)) {
    return leftDate - rightDate;
  }
  return left.localeCompare(right);
};

export const toggleVisibility = (filters: Record<string, boolean>, key: string): Record<string, boolean> => {
  const next: Record<string, boolean> = { ...filters };
  if (!isSafeObjectKey(key)) {
    return next;
  }
  const current = Boolean(getOwnValue(filters, key));
  defineOwnValue(next, key, !current);
  return next;
};

export const setFilterValueFromEvent = (
  filters: Record<string, string>,
  key: string,
  event: Event
): Record<string, string> => {
  const target = event.target as HTMLInputElement | null;
  const next: Record<string, string> = { ...filters };
  if (!isSafeObjectKey(key)) {
    return next;
  }
  defineOwnValue(next, key, target?.value ?? '');
  return next;
};

export const toggleSort = (
  currentColumn: string | null,
  currentDirection: SortDirection,
  targetColumn: string,
  defaultDir: SortDirection = 'asc'
): { column: string; direction: SortDirection } => {
  if (currentColumn === targetColumn) {
    return { column: targetColumn, direction: currentDirection === 'asc' ? 'desc' : 'asc' };
  }
  return { column: targetColumn, direction: defaultDir };
};
