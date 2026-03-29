import { AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { getOwnValue } from '../../../../shared/utils/safe-object';

export type SortDirection = 'asc' | 'desc';

export const buildStringRecord = <T extends string>(
  keys: readonly T[],
  initial = ''
): Record<T, string> =>
  Object.fromEntries(keys.map((key) => [key, initial])) as Record<T, string>;

export const buildBooleanRecord = <T extends string>(
  keys: readonly T[],
  initial = false
): Record<T, boolean> =>
  Object.fromEntries(keys.map((key) => [key, initial])) as Record<T, boolean>;

export const buildModeRecord = <T extends string>(
  keys: readonly T[],
  mode: AdvancedFilterMode
): Record<T, AdvancedFilterMode> =>
  Object.fromEntries(keys.map((key) => [key, mode])) as Record<T, AdvancedFilterMode>;

export const buildMultiRecord = <T extends string>(keys: readonly T[]): Record<T, string[]> =>
  Object.fromEntries(keys.map((key) => [key, [] as string[]])) as Record<T, string[]>;

export const togglePanelState = (current: boolean): boolean => !current;

export const moveColumnOrder = <T>(
  order: readonly T[],
  previousIndex: number,
  currentIndex: number
): T[] => {
  const next = [...order];
  if (
    previousIndex < 0 ||
    previousIndex >= next.length ||
    currentIndex < 0 ||
    currentIndex >= next.length
  ) {
    return next;
  }
  const [item] = next.splice(previousIndex, 1);
  if (item === undefined) {
    return next;
  }
  next.splice(currentIndex, 0, item);
  return next;
};

export const removeColumnFromOrder = <T extends string>(
  order: readonly T[],
  key: T,
  locked: readonly T[]
): T[] => {
  if (locked.includes(key)) {
    return [...order];
  }
  const next = order.filter((entry) => entry !== key);
  return next.length > 0 ? next : [...order];
};

export const addColumnToOrder = <T extends string>(order: readonly T[], key: T): T[] =>
  order.includes(key) ? [...order] : [...order, key];

export const setRecordValue = <T extends string, TValue>(
  state: Record<T, TValue>,
  key: T,
  value: TValue
): Record<T, TValue> => ({ ...state, [key]: value });

export const toggleRecordBoolean = <T extends string>(
  state: Record<T, boolean>,
  key: T
): Record<T, boolean> =>
  setRecordValue(
    state,
    key,
    !getOwnValue(state as unknown as Record<string, unknown>, String(key))
  );

export const setRecordValueFromEvent = <T extends string>(
  state: Record<T, string>,
  key: T,
  event: Event
): Record<T, string> => {
  const target = event.target as HTMLInputElement | null;
  return setRecordValue(state, key, target?.value ?? '');
};

export const applyFilterModeChange = <T extends string>(
  modeState: Record<T, AdvancedFilterMode>,
  valueState: Record<T, string>,
  multiState: Record<T, string[]>,
  key: T,
  mode: AdvancedFilterMode
): {
  modes: Record<T, AdvancedFilterMode>;
  values: Record<T, string>;
  multi: Record<T, string[]>;
} => {
  if (mode === 'contains') {
    return {
      modes: setRecordValue(modeState, key, mode),
      values: valueState,
      multi: setRecordValue(multiState, key, [])
    };
  }
  return {
    modes: setRecordValue(modeState, key, mode),
    values: setRecordValue(valueState, key, ''),
    multi: multiState
  };
};

export const toggleSortState = <T extends string>(
  currentColumn: T | null,
  currentDirection: SortDirection,
  targetColumn: T,
  defaultDirection: SortDirection = 'asc'
): { column: T; direction: SortDirection } => {
  if (currentColumn !== targetColumn) {
    return { column: targetColumn, direction: defaultDirection };
  }
  return {
    column: targetColumn,
    direction: currentDirection === 'asc' ? 'desc' : 'asc'
  };
};

export const normalizePageSize = (size: number, fallback: number): number =>
  size > 0 ? size : fallback;

export const prevPageIndex = (current: number): number => (current <= 0 ? 0 : current - 1);

export const nextPageIndex = (current: number, totalPages: number): number =>
  current + 1 >= totalPages ? current : current + 1;

export const toggleExpandedRowId = (
  expanded: ReadonlySet<string>,
  id: string | number
): Set<string> => {
  const key = String(id);
  const next = new Set(expanded);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  return next;
};
