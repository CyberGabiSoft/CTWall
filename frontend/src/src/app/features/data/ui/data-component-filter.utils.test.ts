import { describe, expect, it } from 'vitest';
import { ComponentSummary } from '../data-access/data.types';
import {
  DataComponentFilterState,
  filterComponentRows
} from './data-component-filter.utils';

const baseState: DataComponentFilterState = {
  filters: {
    purl: '',
    type: '',
    name: '',
    version: '',
    namespace: '',
    licenses: '',
    sbomType: '',
    publisher: '',
    supplier: '',
    malwareVerdict: '',
    malwareTriageStatus: '',
    malwareScannedAt: '',
    malwareValidUntil: ''
  },
  modes: {
    purl: 'contains',
    type: 'contains',
    name: 'contains',
    version: 'contains',
    namespace: 'contains',
    licenses: 'contains',
    sbomType: 'contains',
    publisher: 'contains',
    supplier: 'contains',
    malwareVerdict: 'contains',
    malwareTriageStatus: 'contains',
    malwareScannedAt: 'contains',
    malwareValidUntil: 'contains'
  },
  multi: {
    type: [],
    namespace: [],
    licenses: [],
    sbomType: [],
    publisher: [],
    supplier: []
  }
};

function row(id: string, overrides: Partial<ComponentSummary> = {}): ComponentSummary {
  return {
    id,
    purl: `pkg:npm/test/${id}@1.0.0`,
    pkgName: id,
    version: '1.0.0',
    pkgType: 'npm',
    pkgNamespace: 'test',
    licenses: ['MIT'],
    sbomType: 'cyclonedx',
    publisher: 'acme',
    supplier: 'acme',
    ...overrides
  };
}

describe('data-component-filter.utils', () => {
  it('filters by contains-based fields', () => {
    const state: DataComponentFilterState = {
      ...baseState,
      filters: {
        ...baseState.filters,
        name: 'alpha'
      }
    };

    const rows = [row('alpha-core'), row('beta-core')];
    const result = filterComponentRows(rows, state, () => null);
    expect(result.map((item) => item.pkgName)).toEqual(['alpha-core']);
  });

  it('filters by select-based multi values for license', () => {
    const state: DataComponentFilterState = {
      ...baseState,
      modes: {
        ...baseState.modes,
        licenses: 'select'
      },
      multi: {
        ...baseState.multi,
        licenses: ['GPL-3.0']
      }
    };
    const rows = [
      row('alpha', { licenses: ['MIT'] }),
      row('beta', { licenses: ['GPL-3.0'] })
    ];
    const result = filterComponentRows(rows, state, () => null);
    expect(result.map((item) => item.pkgName)).toEqual(['beta']);
  });

  it('filters by malware verdict fields', () => {
    const state: DataComponentFilterState = {
      ...baseState,
      filters: {
        ...baseState.filters,
        malwareVerdict: 'MALWARE'
      }
    };
    const rows = [row('alpha'), row('beta')];
    const result = filterComponentRows(rows, state, (purl) => ({
      id: `res-${purl}`,
      componentPurl: purl,
      verdict: purl.includes('alpha') ? 'MALWARE' : 'CLEAN',
      scannedAt: null,
      validUntil: null
    }));
    expect(result.map((item) => item.pkgName)).toEqual(['alpha']);
  });
});
