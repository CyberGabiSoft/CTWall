import { describe, expect, it } from 'vitest';
import { mapDeleteValue, mapGetValue, mapSetValue } from './map-utils';

describe('map-utils', () => {
  it('sets value immutably', () => {
    const source = new Map<string, number>([['a', 1]]);
    const next = mapSetValue(source, 'b', 2);

    expect(source).not.toBe(next);
    expect(source.has('b')).toBe(false);
    expect(next.get('b')).toBe(2);
  });

  it('gets value by key', () => {
    const source = new Map<string, string>([['key', 'value']]);
    expect(mapGetValue(source, 'key')).toBe('value');
    expect(mapGetValue(source, 'missing')).toBeUndefined();
  });

  it('deletes value immutably', () => {
    const source = new Map<string, string>([['a', 'x'], ['b', 'y']]);
    const next = mapDeleteValue(source, 'a');

    expect(source).not.toBe(next);
    expect(source.has('a')).toBe(true);
    expect(next.has('a')).toBe(false);
  });
});
