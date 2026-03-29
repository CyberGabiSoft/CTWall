import { MalwareResultSummary } from '../data-access/malware-analysis.types';
import { ComponentSummary } from '../data-access/data.types';
import { extractLicenseValues, formatLicensesDetail } from './data-licenses.utils';

type FilterMode = 'contains' | 'select';

export interface DataComponentFilterState {
  filters: {
    purl: string;
    type: string;
    name: string;
    version: string;
    namespace: string;
    licenses: string;
    sbomType: string;
    publisher: string;
    supplier: string;
    malwareVerdict: string;
    malwareScannedAt: string;
    malwareValidUntil: string;
  };
  modes: {
    purl: FilterMode;
    type: FilterMode;
    name: FilterMode;
    version: FilterMode;
    namespace: FilterMode;
    licenses: FilterMode;
    sbomType: FilterMode;
    publisher: FilterMode;
    supplier: FilterMode;
    malwareVerdict: FilterMode;
    malwareScannedAt: FilterMode;
    malwareValidUntil: FilterMode;
  };
  multi: {
    type: string[];
    namespace: string[];
    licenses: string[];
    sbomType: string[];
    publisher: string[];
    supplier: string[];
  };
}

export type ComponentMalwareLookup = (componentPurl: string) => MalwareResultSummary | null;

export function filterComponentRows(
  rows: ComponentSummary[],
  state: DataComponentFilterState,
  malwareLookup: ComponentMalwareLookup
): ComponentSummary[] {
  const { filters, modes, multi } = state;

  return rows.filter((row) => {
    if (!matchesFilter(row.purl ?? '', filters.purl, modes.purl)) {
      return false;
    }
    if (!matchesFilter(row.pkgName ?? '', filters.name, modes.name)) {
      return false;
    }
    if (!matchesFilter(row.version ?? '', filters.version, modes.version)) {
      return false;
    }
    if (modes.type === 'contains') {
      if (hasText(filters.type) && !contains(row.pkgType ?? '', filters.type)) {
        return false;
      }
    } else if (multi.type.length > 0) {
      if (!multi.type.includes(row.pkgType ?? '')) {
        return false;
      }
    }
    if (modes.namespace === 'contains') {
      if (hasText(filters.namespace) && !contains(row.pkgNamespace ?? '', filters.namespace)) {
        return false;
      }
    } else if (multi.namespace.length > 0) {
      if (!multi.namespace.includes(row.pkgNamespace ?? '')) {
        return false;
      }
    }
    const licenseText = formatLicensesDetail(row.licenses);
    if (modes.licenses === 'contains') {
      if (hasText(filters.licenses) && !contains(licenseText, filters.licenses)) {
        return false;
      }
    } else if (multi.licenses.length > 0) {
      const values = extractLicenseValues(row.licenses);
      if (!multi.licenses.some((value) => values.includes(value))) {
        return false;
      }
    }
    if (modes.sbomType === 'contains') {
      if (hasText(filters.sbomType) && !contains(row.sbomType ?? '', filters.sbomType)) {
        return false;
      }
    } else if (multi.sbomType.length > 0) {
      if (!multi.sbomType.includes(row.sbomType ?? '')) {
        return false;
      }
    }
    if (modes.publisher === 'contains') {
      if (hasText(filters.publisher) && !contains(row.publisher ?? '', filters.publisher)) {
        return false;
      }
    } else if (multi.publisher.length > 0) {
      if (!multi.publisher.includes(row.publisher ?? '')) {
        return false;
      }
    }
    if (modes.supplier === 'contains') {
      if (hasText(filters.supplier) && !contains(row.supplier ?? '', filters.supplier)) {
        return false;
      }
    } else if (multi.supplier.length > 0) {
      if (!multi.supplier.includes(row.supplier ?? '')) {
        return false;
      }
    }
    const malware = malwareLookup(row.purl ?? '');
    const malwareVerdict = malware?.verdict ?? '';
    const malwareScannedAt = malware?.scannedAt ?? '';
    const malwareValidUntil = malware?.validUntil ?? '';

    if (!matchesFilter(malwareVerdict, filters.malwareVerdict, modes.malwareVerdict)) {
      return false;
    }
    if (!matchesFilter(malwareScannedAt, filters.malwareScannedAt, modes.malwareScannedAt)) {
      return false;
    }
    if (!matchesFilter(malwareValidUntil, filters.malwareValidUntil, modes.malwareValidUntil)) {
      return false;
    }
    return true;
  });
}

function hasText(value: string): boolean {
  return value.trim().length > 0;
}

function contains(source: string, needle: string): boolean {
  return source.toLowerCase().includes(needle.trim().toLowerCase());
}

function matchesFilter(source: string, needle: string, mode: FilterMode): boolean {
  if (!hasText(needle)) {
    return true;
  }
  if (mode === 'select') {
    return source.trim().toLowerCase() === needle.trim().toLowerCase();
  }
  return contains(source, needle);
}
