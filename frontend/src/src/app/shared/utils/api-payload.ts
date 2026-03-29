export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

// Many endpoints return either `T[]` or `{ items: T[] }`. Normalize to an array.
export const extractItems = <T>(value: unknown): T[] => {
  if (Array.isArray(value)) {
    return value as T[];
  }
  if (isRecord(value) && Array.isArray(value['items'])) {
    return value['items'] as T[];
  }
  return [];
};

