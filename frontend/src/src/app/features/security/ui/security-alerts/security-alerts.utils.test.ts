import { describe, expect, it } from 'vitest';
import {
  connectorRouteIds,
  groupDedupRule,
  isNilUUID,
  matchesAdvancedFilter,
  normalizeDedupRules,
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
