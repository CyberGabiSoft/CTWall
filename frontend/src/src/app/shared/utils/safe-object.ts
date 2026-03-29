const forbiddenKeys = new Set(['__proto__', 'prototype', 'constructor']);

export const isSafeObjectKey = (key: string): boolean => {
  const trimmed = key.trim();
  if (!trimmed) {
    return false;
  }
  return !forbiddenKeys.has(trimmed);
};

export const getOwnValue = <T>(obj: Record<string, T>, key: string): T | undefined => {
  if (!isSafeObjectKey(key)) {
    return undefined;
  }
  return Object.getOwnPropertyDescriptor(obj, key)?.value as T | undefined;
};

export const defineOwnValue = <T>(obj: Record<string, T>, key: string, value: T): void => {
  if (!isSafeObjectKey(key)) {
    return;
  }
  Object.defineProperty(obj, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true
  });
};

