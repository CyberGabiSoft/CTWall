export function formatLicensesDetail(licenses: unknown): string {
  if (!licenses) {
    return '-';
  }

  if (Array.isArray(licenses)) {
    const labels = licenses
      .map((license) => normalizeLicenseEntry(license))
      .filter((value): value is string => Boolean(value));

    return labels.length > 0 ? labels.join(', ') : '-';
  }

  if (typeof licenses === 'string') {
    return licenses;
  }

  try {
    return JSON.stringify(licenses);
  } catch {
    return '-';
  }
}

export function extractLicenseValues(licenses: unknown): string[] {
  if (!licenses) {
    return [];
  }
  if (Array.isArray(licenses)) {
    const values: string[] = [];
    for (const license of licenses) {
      const normalized = normalizeLicenseEntry(license);
      if (normalized && normalized.trim().length > 0) {
        values.push(normalized);
      }
    }
    return values;
  }
  if (typeof licenses === 'string') {
    return licenses
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
  }
  return [];
}

export function hasLicenses(licenses: unknown): boolean {
  if (!licenses) {
    return false;
  }
  if (Array.isArray(licenses)) {
    return licenses.length > 0;
  }
  return true;
}

function normalizeLicenseEntry(license: unknown): string | null {
  if (!license) {
    return null;
  }
  if (typeof license === 'string') {
    return license;
  }
  if (typeof license === 'object') {
    const record = license as Record<string, unknown>;
    if (typeof record['id'] === 'string') {
      return record['id'] as string;
    }
    if (typeof record['name'] === 'string') {
      return record['name'] as string;
    }
    const nested = record['license'] as Record<string, unknown> | undefined;
    if (nested) {
      if (typeof nested['id'] === 'string') {
        return nested['id'] as string;
      }
      if (typeof nested['name'] === 'string') {
        return nested['name'] as string;
      }
    }
  }
  try {
    return JSON.stringify(license);
  } catch {
    return null;
  }
}
