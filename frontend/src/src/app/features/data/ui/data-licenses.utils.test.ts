import { describe, expect, it } from 'vitest';
import {
  extractLicenseValues,
  formatLicensesDetail,
  hasLicenses
} from './data-licenses.utils';

describe('data-licenses.utils', () => {
  it('formats array licenses into comma-separated labels', () => {
    const value = formatLicensesDetail([
      { id: 'MIT' },
      { name: 'Apache-2.0' },
      { license: { id: 'BSD-3-Clause' } }
    ]);
    expect(value).toBe('MIT, Apache-2.0, BSD-3-Clause');
  });

  it('extracts normalized license values', () => {
    const values = extractLicenseValues('MIT, Apache-2.0 , BSD-3-Clause');
    expect(values).toEqual(['MIT', 'Apache-2.0', 'BSD-3-Clause']);
  });

  it('detects license presence', () => {
    expect(hasLicenses([])).toBe(false);
    expect(hasLicenses(['MIT'])).toBe(true);
    expect(hasLicenses('MIT')).toBe(true);
  });
});
