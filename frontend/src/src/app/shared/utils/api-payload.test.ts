import { describe, expect, it } from 'vitest';
import { extractItems, isRecord } from './api-payload';

describe('api-payload', () => {
  it('detects plain records', () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(true); // arrays are objects; caller must handle separately
    expect(isRecord(null)).toBe(false);
    expect(isRecord('x')).toBe(false);
  });

  it('extracts items from array payload', () => {
    expect(extractItems<number>([1, 2, 3])).toEqual([1, 2, 3]);
  });

  it('extracts items from {items: T[]} payload', () => {
    expect(extractItems<number>({ items: [1, 2] })).toEqual([1, 2]);
  });

  it('returns empty array for unsupported payloads', () => {
    expect(extractItems<number>({})).toEqual([]);
    expect(extractItems<number>(null)).toEqual([]);
    expect(extractItems<number>('nope')).toEqual([]);
  });
});

