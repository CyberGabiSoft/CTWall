import { describe, expect, it } from 'vitest';
import {
  connectorRouteIds,
  formatDetectionData,
  groupDetectionData,
  groupDetectionMode,
  groupDedupRule,
  isNilUUID,
  matchesAdvancedFilter,
  normalizeDedupRules,
  normalizeDetectionModeCode,
  normalizeMatchTypeCode,
  occurrenceDetectionData,
  occurrenceDetectionMode,
  normalizeMinSeverity,
  serializeDedupRules
} from './security-alerts.utils';

describe('security-alerts.utils', () => {
  it('matches contains and select filter modes', () => {
    expect(matchesAdvancedFilter('Malware detected', 'contains', 'malware', [])).toBe(true);
    expect(matchesAdvancedFilter('ERROR', 'select', '', ['ERROR'])).toBe(true);
    expect(matchesAdvancedFilter('ERROR', 'select', '', ['WARNING'])).toBe(false);
  });

  it('resolves dedup rule label from group key', () => {
    expect(groupDedupRule('dedup_on:test|test_id:abc-123')).toBe('TEST (abc-123)');
    expect(groupDedupRule('dedup_on:global')).toBe('GLOBAL');
  });

  it('normalizes and extracts detection modes', () => {
    expect(normalizeDetectionModeCode('PURL_VERSION_SMART')).toBe('purl_version_smart');
    expect(groupDetectionMode('detect_mode:purl_contains_prefix|dedup_on:test')).toBe('purl_contains_prefix');
    expect(occurrenceDetectionMode({ detectMode: 'PURL_CONTAINS_PREFIX' })).toBe('purl_contains_prefix');
  });

  it('builds detection data strings', () => {
    expect(normalizeMatchTypeCode('contains_prefix')).toBe('CONTAINS_PREFIX');
    const exact = formatDetectionData(
      'pkg:npm/component@1.0.0',
      'pkg:npm/mal@1.0.0',
      'EXACT',
      'purl_version_smart'
    );
    expect(exact).toContain('pkg:npm/component@1.0.0 -> pkg:npm/mal@1.0.0');
    expect(exact).toContain('base+version');
    expect(exact).toContain('pkg:npm/component@1.0.0 == pkg:npm/mal@1.0.0');

    const groupPrefix = groupDetectionData('detect_mode:purl_contains_prefix|malware_purl:pkg:npm/mal@1.0.0');
    expect(groupPrefix).toContain('* -> pkg:npm/mal@1.0.0');
    expect(groupPrefix).toContain('base:');
    expect(groupPrefix).toContain('* == pkg:npm/mal');

    const componentPrefix = groupDetectionData(
      'detect_mode:purl_contains_prefix|malware_purl:pkg:npm/mal@1.0.0',
      'pkg:npm/component@1.0.0'
    );
    expect(componentPrefix).toContain('pkg:npm/component@1.0.0 -> pkg:npm/mal@1.0.0');
    expect(componentPrefix).toContain('base: pkg:npm/component == pkg:npm/mal');
    expect(
      occurrenceDetectionData(
        {
          componentPurl: 'pkg:npm/component@1.0.0',
          malwarePurl: 'pkg:npm/mal@1.0.0',
          matchType: 'CONTAINS_PREFIX',
          detectMode: 'PURL_CONTAINS_PREFIX'
        },
        ''
      )
    ).toContain('base: pkg:npm/component == pkg:npm/mal');
  });

  it('normalizes severity and dedup rules serialization', () => {
    const normalized = normalizeDedupRules([
      {
        id: '1',
        projectId: 'project-1',
        alertType: ' malware.detected ',
        dedupScope: 'TEST',
        minSeverity: 'WARNING',
        productId: ' ',
        scopeId: ' ',
        testId: ' test-1 ',
        enabled: true
      }
    ]);
    expect(normalized[0].minSeverity).toBe('WARNING');
    expect(normalizeMinSeverity('error')).toBe('ERROR');
    expect(serializeDedupRules(normalized)).toContain('"testId":"test-1"');
  });

  it('extracts connector route ids by target type', () => {
    const ids = connectorRouteIds(
      {
        type: 'jira',
        projectId: 'project-1',
        alertingEnabled: true,
        jiraDedupRuleId: null,
        routes: [
          { targetType: 'PRODUCT', targetId: 'p1' },
          { targetType: 'SCOPE', targetId: 's1' },
          { targetType: 'PRODUCT', targetId: 'p1' }
        ],
        connectionStatus: {
          configured: true,
          connectionEnabled: true,
          lastTestStatus: 'PASSED',
          lastTestAt: null,
          lastTestMessage: null
        }
      },
      'PRODUCT'
    );
    expect(ids).toEqual(['p1']);
  });

  it('recognizes nil UUID values', () => {
    expect(isNilUUID('00000000-0000-0000-0000-000000000000')).toBe(true);
    expect(isNilUUID('d8ac8ba4-2af8-4f5b-9f4a-e2dd089f3b5d')).toBe(false);
  });
});
