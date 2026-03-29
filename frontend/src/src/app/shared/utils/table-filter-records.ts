import { ColumnDefinition } from '../ui/data-table/data-table.types';
import { defineOwnValue, isSafeObjectKey } from './safe-object';

export type FilterMode = 'contains' | 'select';

export const buildFilterVisibility = (
  definitions: readonly ColumnDefinition[],
): Record<string, boolean> =>
  definitions.reduce<Record<string, boolean>>((acc, column) => {
    const key = column.filterKey;
    if (isSafeObjectKey(key)) {
      defineOwnValue(acc, key, false);
    }
    return acc;
  }, {});

export const buildFilterValues = (definitions: readonly ColumnDefinition[]): Record<string, string> =>
  definitions.reduce<Record<string, string>>((acc, column) => {
    const key = column.filterKey;
    if (isSafeObjectKey(key)) {
      defineOwnValue(acc, key, '');
    }
    return acc;
  }, {});

export const buildFilterModes = (
  keys: readonly string[],
  defaultMode: FilterMode = 'contains',
): Record<string, FilterMode> =>
  keys.reduce<Record<string, FilterMode>>((acc, key) => {
    if (isSafeObjectKey(key)) {
      defineOwnValue(acc, key, defaultMode);
    }
    return acc;
  }, {});

export const buildMultiFilters = (keys: readonly string[]): Record<string, string[]> =>
  keys.reduce<Record<string, string[]>>((acc, key) => {
    if (isSafeObjectKey(key)) {
      defineOwnValue(acc, key, []);
    }
    return acc;
  }, {});
