export const mapSetValue = <K, V>(source: Map<K, V>, key: K, value: V): Map<K, V> => {
  const next = new Map(source);
  next.set(key, value);
  return next;
};

export const mapGetValue = <K, V>(source: Map<K, V>, key: K): V | undefined => source.get(key);

export const mapDeleteValue = <K, V>(source: Map<K, V>, key: K): Map<K, V> => {
  const next = new Map(source);
  next.delete(key);
  return next;
};
