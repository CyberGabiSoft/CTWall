import { describe, expect, it } from 'vitest';
import {
  addOption,
  anyFilterValue,
  anyFilterVisible,
  appendFilterParams,
  enableAllVisibility,
  filterByColumns,
  paginate,
  setFilterValue,
  sortRows,
  toggleSort,
  toggleVisibility,
  visibilityFromValues
} from './data-table.utils';

describe('data-table.utils', () => {
  it('appends only non-empty trimmed params', () => {
    const params: Record<string, string> = {};
    appendFilterParams(params, 'pf_', {
      name: ' abc ',
      id: ' ',
      updated: ''
    });
    expect(params).toEqual({ pf_name: 'abc' });
  });

  it('builds filter visibility and can force all true', () => {
    const visibility = visibilityFromValues({ a: '', b: 'x' });
    expect(visibility).toEqual({ a: false, b: true });
    expect(enableAllVisibility(visibility)).toEqual({ a: true, b: true });
  });

  it('filters rows in contains and select mode', () => {
    const rows = [
      { name: 'alpha', status: 'OPEN' },
      { name: 'beta', status: 'CLOSED' }
    ];
    const containsFiltered = filterByColumns(
      rows,
      { name: 'alp', status: '' },
      { name: 'contains', status: 'contains' },
      (row) => ({ name: row.name, status: row.status })
    );
    expect(containsFiltered.map((row) => row.name)).toEqual(['alpha']);

    const selectFiltered = filterByColumns(
      rows,
      { name: '', status: '' },
      { name: 'contains', status: 'select' },
      (row) => ({ name: row.name, status: row.status }),
      { status: ['CLOSED'] }
    );
    expect(selectFiltered.map((row) => row.name)).toEqual(['beta']);
  });

  it('sorts and paginates rows', () => {
    const rows = [{ n: 2 }, { n: 1 }, { n: 3 }];
    const asc = sortRows(rows, 'n', 'asc', (row) => row.n);
    const desc = sortRows(rows, 'n', 'desc', (row) => row.n);
    expect(asc.map((row) => row.n)).toEqual([1, 2, 3]);
    expect(desc.map((row) => row.n)).toEqual([3, 2, 1]);
    expect(paginate(asc, 1, 2).map((row) => row.n)).toEqual([3]);
  });

  it('updates visibility and filter values safely', () => {
    const visibility = toggleVisibility({ name: false }, 'name');
    expect(visibility.name).toBe(true);

    const unsafeVisibility = toggleVisibility({ name: false }, '__proto__' as 'name');
    expect(unsafeVisibility).toEqual({ name: false });

    const event = { target: { value: 'new' } } as unknown as Event;
    const filters = setFilterValue({ name: '' }, 'name', event);
    expect(filters).toEqual({ name: 'new' });
  });

  it('toggles sort direction for active column', () => {
    const columnState = { value: 'name' };
    const directionState = { value: 'asc' as 'asc' | 'desc' };
    const columnSignal = Object.assign(() => columnState.value, {
      set: (value: string) => {
        columnState.value = value;
      }
    });
    const directionSignal = Object.assign(() => directionState.value, {
      set: (value: 'asc' | 'desc') => {
        directionState.value = value;
      }
    });

    toggleSort(columnSignal, directionSignal, 'name', 'asc');
    expect(directionState.value).toBe('desc');

    toggleSort(columnSignal, directionSignal, 'updated', 'desc');
    expect(columnState.value).toBe('updated');
    expect(directionState.value).toBe('desc');
  });

  it('handles option and filter summary checks', () => {
    const options = new Set<string>();
    addOption(options, 'abc');
    addOption(options, '   ');
    addOption(options, '-');
    expect(Array.from(options)).toEqual(['abc']);

    expect(anyFilterVisible({ a: false, b: true })).toBe(true);
    expect(anyFilterValue({ a: ' ', b: 'x' })).toBe(true);
  });
});
