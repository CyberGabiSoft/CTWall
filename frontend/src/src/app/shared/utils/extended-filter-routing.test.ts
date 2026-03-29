import { convertToParamMap } from '@angular/router';
import { describe, expect, it } from 'vitest';
import {
  buildExtendedFilterContextQueryParams,
  buildExtendedFilterQueryParams,
  readExtendedFilterContextQueryParams,
  readExtendedFilterQueryParams
} from './extended-filter-routing';

describe('extended-filter-routing', () => {
  it('builds and reads contains/select filters with canonical query keys', () => {
    const built = buildExtendedFilterQueryParams('malware_summary', {
      test: { mode: 'select', values: ['Test-A', 'Test-B'] },
      product: { mode: 'contains', value: 'ManualProduct' }
    });
    const paramMap = convertToParamMap(built as Record<string, string>);
    const parsed = readExtendedFilterQueryParams(paramMap, {
      tableId: 'malware_summary',
      keys: ['test', 'product'] as const
    });

    expect(parsed.hasAny).toBe(true);
    expect(parsed.mode.test).toBe('select');
    expect(parsed.values.test).toEqual(['Test-A', 'Test-B']);
    expect(parsed.mode.product).toBe('contains');
    expect(parsed.value.product).toBe('ManualProduct');
  });

  it('reads legacy aliases when canonical keys are absent', () => {
    const paramMap = convertToParamMap({
      focusTestId: 'test-123',
      componentPurl: 'pkg:npm/demo@1.0.0'
    });

    const parsed = readExtendedFilterContextQueryParams(paramMap, {
      tableId: 'malware_summary',
      keys: ['testId', 'componentPurl'] as const,
      aliases: {
        testId: ['focusTestId'],
        componentPurl: ['componentPurl']
      }
    });

    expect(parsed.testId).toBe('test-123');
    expect(parsed.componentPurl).toBe('pkg:npm/demo@1.0.0');
  });

  it('builds context params and preserves null for empty values', () => {
    const built = buildExtendedFilterContextQueryParams('malware_summary', {
      productId: 'p-1',
      scopeId: ''
    });

    expect(built['ef_malware_summary_ctx_productId']).toBe('p-1');
    expect(built['ef_malware_summary_ctx_scopeId']).toBeNull();
  });
});

