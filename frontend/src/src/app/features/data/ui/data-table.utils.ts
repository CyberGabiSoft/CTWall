import { ColumnDefinition } from './data.columns';
import { defineOwnValue, getOwnValue, isSafeObjectKey } from '../../../shared/utils/safe-object';

export const appendFilterParams = (
  params: Record<string, string>,
  prefix: string,
  filters: Record<string, string>
): void => {
  for (const [key, value] of Object.entries(filters)) {
    const trimmed = value.trim();
    if (trimmed.length > 0) {
      params[`${prefix}${key}`] = trimmed;
    }
  }
};

export const visibilityFromValues = <T extends Record<string, string>>(filters: T): Record<keyof T, boolean> =>
  Object.fromEntries(
    Object.entries(filters).map(([key, value]) => [key, value.trim().length > 0])
  ) as Record<keyof T, boolean>;

export const enableAllVisibility = <T extends Record<string, boolean>>(filters: T): T =>
  Object.fromEntries(Object.keys(filters).map((key) => [key, true])) as T;

export const filterByColumns = <
  T,
  F extends Record<string, string>,
  M extends Record<keyof F, 'contains' | 'select'>,
>(
  items: T[],
  filters: F,
  modes: M,
  values: (item: T) => Record<keyof F, string>,
  multiFilters?: Partial<Record<keyof F, string[]>>
): T[] => {
  // Keys may come from dynamic sources (URL/localStorage). Guard against prototype pollution primitives.
  const keys = Object.keys(filters)
    .filter((key) => isSafeObjectKey(key))
    .sort() as Array<keyof F>;
  const filterRecord = filters as unknown as Record<string, unknown>;
  const modesRecord = modes as unknown as Record<string, unknown>;
  const multiRecord = multiFilters as unknown as Record<string, unknown> | undefined;
  const hasAnyTextFilter = keys.some((key) => {
    const value = getOwnValue(filterRecord, String(key));
    return typeof value === 'string' && value.trim().length > 0;
  });
  const hasAnyMultiFilter = keys.some((key) => {
    const selected = getOwnValue(multiRecord ?? {}, String(key));
    return Array.isArray(selected) && selected.length > 0;
  });
  if (!hasAnyTextFilter && !hasAnyMultiFilter) {
    return items;
  }
  return items.filter((item) => {
    const row = values(item) as unknown as Record<string, unknown>;
    return keys.every((key) => {
      const cellValue = getOwnValue(row, String(key));
      const cell = String(cellValue ?? '');
      const modeValue = getOwnValue(modesRecord, String(key));
      const mode = modeValue === 'select' ? 'select' : 'contains';
      if (mode === 'select') {
        const selectedValue = getOwnValue(multiRecord ?? {}, String(key));
        const selected = Array.isArray(selectedValue)
          ? selectedValue.filter((entry) => typeof entry === 'string')
          : [];
        if (selected.length > 0) {
          return selected.includes(cell);
        }
        const exactValue = getOwnValue(filterRecord, String(key));
        const exact = typeof exactValue === 'string' ? exactValue.trim() : '';
        if (!exact) {
          return true;
        }
        return cell.trim().toLowerCase() === exact.toLowerCase();
      }
      const queryValue = getOwnValue(filterRecord, String(key));
      const query = typeof queryValue === 'string' ? queryValue.trim() : '';
      if (!query) {
        return true;
      }
      return cell.toLowerCase().includes(query.toLowerCase());
    });
  });
};

export const sortRows = <T, K extends string>(
  items: T[],
  column: K,
  direction: 'asc' | 'desc',
  accessor: (item: T, column: K) => string | number
): T[] => {
  const sorted = [...items].sort((a, b) => {
    const aValue = accessor(a, column);
    const bValue = accessor(b, column);
    if (aValue === bValue) {
      return 0;
    }
    if (aValue === undefined || aValue === null) {
      return 1;
    }
    if (bValue === undefined || bValue === null) {
      return -1;
    }
    if (typeof aValue === 'number' && typeof bValue === 'number') {
      return aValue - bValue;
    }
    return String(aValue).localeCompare(String(bValue));
  });
  return direction === 'asc' ? sorted : sorted.reverse();
};

export const paginate = <T>(items: T[], pageIndex: number, pageSize: number): T[] => {
  if (pageSize <= 0) {
    return items;
  }
  const start = pageIndex * pageSize;
  return items.slice(start, start + pageSize);
};

export const readInputValue = (event: Event): string => {
  const target = event.target as HTMLInputElement | null;
  return target?.value ?? '';
};

export const addOption = (set: Set<string>, value: string): void => {
  const normalized = value.trim();
  if (!normalized || normalized === '-') {
    return;
  }
  set.add(normalized);
};

export const sortOptions = (values: Set<string>): string[] =>
  Array.from(values).sort((a, b) =>
    a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' })
  );

export const orderedColumns = <T extends string, F extends string>(
  definitions: readonly ColumnDefinition<T, F>[],
  order: readonly T[]
): ColumnDefinition<T, F>[] => {
  const map = new Map(definitions.map((def) => [def.key, def]));
  return order.map((key) => map.get(key)).filter(Boolean) as Array<ColumnDefinition<T, F>>;
};

export const availableColumns = <T extends string, F extends string>(
  definitions: readonly ColumnDefinition<T, F>[],
  order: readonly T[],
  query: string
): ColumnDefinition<T, F>[] => {
  const normalized = query.trim().toLowerCase();
  const selected = new Set(order);
  return definitions.filter((def) => {
    if (selected.has(def.key)) {
      return false;
    }
    if (!normalized) {
      return true;
    }
    return def.label.toLowerCase().includes(normalized);
  });
};

export const columnLabel = <T extends string>(
  definitions: readonly { key: T; label: string }[],
  column: T
): string => definitions.find((def) => def.key === column)?.label ?? column;

export const anyFilterVisible = (filters: Record<string, boolean>): boolean =>
  Object.values(filters).some(Boolean);

export const anyFilterValue = (filters: Record<string, string>): boolean =>
  Object.values(filters).some((value) => value.trim().length > 0);

export const toggleVisibility = <T extends Record<string, boolean>, K extends keyof T>(
  filters: T,
  key: K
): T => {
  const next = { ...filters } as T;
  const safeKey = String(key);
  if (!isSafeObjectKey(safeKey)) {
    return next;
  }
  const current = Boolean(getOwnValue(filters as unknown as Record<string, unknown>, safeKey));
  defineOwnValue(next as unknown as Record<string, unknown>, safeKey, !current);
  return next;
};

export const setFilterValue = <T extends Record<string, string>, K extends keyof T>(
  filters: T,
  key: K,
  event: Event
): T => {
  const target = event.target as HTMLInputElement | null;
  const next = { ...filters } as T;
  const safeKey = String(key);
  if (!isSafeObjectKey(safeKey)) {
    return next;
  }
  defineOwnValue(next as unknown as Record<string, unknown>, safeKey, target?.value ?? '');
  return next;
};

export const toggleSort = <T extends string>(
  columnSignal: { (): T; set: (value: T) => void },
  dirSignal: { (): 'asc' | 'desc'; set: (value: 'asc' | 'desc') => void },
  column: T,
  defaultDir: 'asc' | 'desc'
): void => {
  const currentColumn = columnSignal();
  const currentDir = dirSignal();
  if (currentColumn === column) {
    dirSignal.set(currentDir === 'asc' ? 'desc' : 'asc');
    return;
  }
  columnSignal.set(column);
  dirSignal.set(defaultDir);
};
