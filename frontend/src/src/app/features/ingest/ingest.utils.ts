export const NAME_MAX_LENGTH = 120;

export const normalizeName = (value: string): string => value.trim();

export const hasControlCharacters = (value: string): boolean => {
  for (const char of value) {
    const code = char.charCodeAt(0);
    if (code <= 31 || code === 127) {
      return true;
    }
  }
  return false;
};

export const formatBytes = (bytes: number): string => {
  if (!Number.isFinite(bytes)) {
    return '0 B';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  let size = bytes / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < 2) {
    size /= 1024;
    unitIndex += 1;
  }
  const unit = unitIndex === 0 ? 'KB' : unitIndex === 1 ? 'MB' : 'GB';
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${unit}`;
};
