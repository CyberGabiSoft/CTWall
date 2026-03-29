import { convertToParamMap } from '@angular/router';
import { buildReturnToQueryParam, readReturnToQueryParam, sanitizeInternalReturnTo } from './return-navigation';

describe('return-navigation', () => {
  it('accepts only internal paths', () => {
    expect(sanitizeInternalReturnTo('/security/explorer')).toBe('/security/explorer');
    expect(sanitizeInternalReturnTo('/security/explorer?x=1')).toBe('/security/explorer?x=1');
    expect(sanitizeInternalReturnTo('https://example.com')).toBeNull();
    expect(sanitizeInternalReturnTo('//example.com')).toBeNull();
    expect(sanitizeInternalReturnTo('javascript:alert(1)')).toBeNull();
    expect(sanitizeInternalReturnTo('security/explorer')).toBeNull();
  });

  it('builds returnTo query param only for valid internal paths', () => {
    expect(buildReturnToQueryParam('/security/explorer')).toEqual({ returnTo: '/security/explorer' });
    expect(buildReturnToQueryParam('https://example.com')).toEqual({});
  });

  it('reads and sanitizes returnTo from query params', () => {
    const valid = convertToParamMap({ returnTo: '/security/explorer?x=1' });
    expect(readReturnToQueryParam(valid)).toBe('/security/explorer?x=1');

    const invalid = convertToParamMap({ returnTo: 'https://example.com/path' });
    expect(readReturnToQueryParam(invalid)).toBeNull();
  });
});

