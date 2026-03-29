import { describe, expect, it } from 'vitest';
import {
  addColumnToOrder,
  applyFilterModeChange,
  buildBooleanRecord,
  buildModeRecord,
  buildMultiRecord,
  buildStringRecord,
  moveColumnOrder,
  nextPageIndex,
  normalizePageSize,
  prevPageIndex,
  removeColumnFromOrder,
  setRecordValueFromEvent,
  toggleExpandedRowId,
  togglePanelState,
  toggleRecordBoolean,
  toggleSortState,
} from './security-alerts.table-state';

describe('security-alerts.table-state', () => {
  it('builds default records from keys', () => {
    const keys = ['a', 'b'] as const;
    expect(buildStringRecord(keys)).toEqual({ a: '', b: '' });
    expect(buildBooleanRecord(keys)).toEqual({ a: false, b: false });
    expect(buildModeRecord(keys, 'contains')).toEqual({ a: 'contains', b: 'contains' });
    expect(buildMultiRecord(keys)).toEqual({ a: [], b: [] });
  });

  it('handles panel and column order operations', () => {
    expect(togglePanelState(false)).toBe(true);
    expect(moveColumnOrder(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a']);
    expect(removeColumnFromOrder(['a', 'b'], 'a', ['b'])).toEqual(['b']);
    expect(removeColumnFromOrder(['a'], 'a', [])).toEqual(['a']);
    expect(addColumnToOrder(['a'], 'b')).toEqual(['a', 'b']);
    expect(addColumnToOrder(['a'], 'a')).toEqual(['a']);
  });

  it('updates records and filter mode transitions', () => {
    expect(toggleRecordBoolean({ a: false }, 'a')).toEqual({ a: true });

    const event = { target: { value: 'abc' } } as unknown as Event;
    expect(setRecordValueFromEvent({ a: '' }, 'a', event)).toEqual({ a: 'abc' });

    const contains = applyFilterModeChange(
      { a: 'select' },
      { a: 'x' },
      { a: ['x'] },
      'a',
      'contains'
    );
    expect(contains.modes).toEqual({ a: 'contains' });
    expect(contains.values).toEqual({ a: 'x' });
    expect(contains.multi).toEqual({ a: [] });

    const select = applyFilterModeChange(
      { a: 'contains' },
      { a: 'x' },
      { a: [] },
      'a',
      'select'
    );
    expect(select.modes).toEqual({ a: 'select' });
    expect(select.values).toEqual({ a: '' });
    expect(select.multi).toEqual({ a: [] });
  });

  it('handles sort and pagination helpers', () => {
    expect(toggleSortState('a', 'asc', 'a')).toEqual({ column: 'a', direction: 'desc' });
    expect(toggleSortState('a', 'desc', 'b')).toEqual({ column: 'b', direction: 'asc' });
    expect(toggleSortState('a', 'desc', 'b', 'desc')).toEqual({ column: 'b', direction: 'desc' });

    expect(normalizePageSize(0, 50)).toBe(50);
    expect(normalizePageSize(10, 50)).toBe(10);
    expect(prevPageIndex(0)).toBe(0);
    expect(prevPageIndex(3)).toBe(2);
    expect(nextPageIndex(1, 3)).toBe(2);
    expect(nextPageIndex(2, 3)).toBe(2);
  });

  it('toggles expanded row ids', () => {
    const expanded = new Set<string>(['a']);
    expect(Array.from(toggleExpandedRowId(expanded, 'a'))).toEqual([]);
    expect(Array.from(toggleExpandedRowId(expanded, 'b'))).toEqual(['a', 'b']);
  });
});
