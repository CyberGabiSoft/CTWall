import { describe, expect, it } from 'vitest';
import { defineOwnValue, getOwnValue, isSafeObjectKey } from './safe-object';

describe('safe-object', () => {
  it('rejects prototype pollution primitives', () => {
    expect(isSafeObjectKey('__proto__')).toBe(false);
    expect(isSafeObjectKey('prototype')).toBe(false);
    expect(isSafeObjectKey('constructor')).toBe(false);
  });

  it('rejects empty and whitespace-only keys', () => {
    expect(isSafeObjectKey('')).toBe(false);
    expect(isSafeObjectKey('   ')).toBe(false);
  });

  it('reads and writes only own properties', () => {
    const obj: Record<string, unknown> = Object.create({ inherited: 'nope' });
    defineOwnValue(obj, 'ok', 'yes');

    expect(getOwnValue(obj, 'ok')).toBe('yes');
    expect(getOwnValue(obj, 'inherited')).toBeUndefined();
  });

  it('does not write forbidden keys', () => {
    const obj: Record<string, unknown> = {};
    defineOwnValue(obj, '__proto__', { polluted: true } as unknown);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });
});

