import { describe, expect, it } from 'vitest';
import { ColumnDefinition } from '../ui/data-table/data-table.types';
import {
  buildFilterModes,
  buildFilterValues,
  buildFilterVisibility,
  buildMultiFilters
} from './table-filter-records';

const columns: ColumnDefinition[] = [
  { key: 'name', label: 'Name', sortKey: 'name', filterKey: 'name' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' }
];

describe('table-filter-records', () => {
  it('builds visibility record', () => {
    expect(buildFilterVisibility(columns)).toEqual({ name: false, status: false });
  });

  it('builds values record', () => {
    expect(buildFilterValues(columns)).toEqual({ name: '', status: '' });
  });

  it('builds modes record with default contains', () => {
    expect(buildFilterModes(['name', 'status'])).toEqual({ name: 'contains', status: 'contains' });
  });

  it('builds modes record with explicit default', () => {
    expect(buildFilterModes(['name'], 'select')).toEqual({ name: 'select' });
  });

  it('builds multi-value record', () => {
    expect(buildMultiFilters(['name', 'status'])).toEqual({ name: [], status: [] });
  });
});
