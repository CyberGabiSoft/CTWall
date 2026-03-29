import { describe, expect, it } from 'vitest';
import {
  COMPONENT_COLUMNS,
  COMPONENT_DEFAULT_COLUMNS,
  LAST_CHANGE_COLUMNS,
  PRODUCT_COLUMNS,
  REVISION_CHANGE_COLUMNS,
  REVISION_COLUMNS,
  SCOPE_COLUMNS,
  TEST_COLUMNS
} from './data.columns';

const unique = <T>(values: T[]): boolean => new Set(values).size === values.length;

describe('data columns', () => {
  it('use unique keys per table', () => {
    expect(unique(PRODUCT_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(SCOPE_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(TEST_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(REVISION_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(LAST_CHANGE_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(REVISION_CHANGE_COLUMNS.map((column) => column.key))).toBe(true);
    expect(unique(COMPONENT_COLUMNS.map((column) => column.key))).toBe(true);
  });

  it('keeps component defaults within defined columns', () => {
    const componentKeys = new Set(COMPONENT_COLUMNS.map((column) => column.key));
    const missing = COMPONENT_DEFAULT_COLUMNS.filter((key) => !componentKeys.has(key));
    expect(missing).toEqual([]);
  });
});
