import { describe, expect, it } from 'vitest';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import {
  acknowledgeActionTooltip,
  alertGroupExpandedItems,
  alertGroupValue,
  alertOccurrenceDetailsJson,
  alertOccurrenceExpandedItems,
  alertOccurrenceValue,
  alertSeverityClass,
  alertStatusClass,
  applyGroupFiltersAndSort,
  applyOccurrenceFiltersAndSort,
  closeActionTooltip,
  isMalwareAlertGroup,
  isMalwareAlertOccurrence,
} from './security-alerts.mapper';

function createGroup(overrides: Partial<AlertGroup> = {}): AlertGroup {
  return {
    id: 'group-1',
    projectId: 'project-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    status: 'OPEN',
    groupKey: 'dedup_on:test|test_id:test-1|malware_purl:pkg:npm/bad@1.2.3',
    title: 'Malware detected in active revision',
    entityRef: 'pkg:npm/leftpad@1.0.0',
    occurrences: 3,
    firstSeenAt: '2026-03-17T10:00:00Z',
    lastSeenAt: '2026-03-17T12:00:00Z',
    createdAt: '2026-03-17T10:00:00Z',
    updatedAt: '2026-03-17T12:00:00Z',
    ...overrides,
  };
}

function createOccurrence(overrides: Partial<AlertOccurrence> = {}): AlertOccurrence {
  return {
    id: 'occ-1',
    projectId: 'project-1',
    groupId: 'group-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    title: 'Malware occurrence',
    occurredAt: '2026-03-17T12:00:00Z',
    productId: 'product-1',
    scopeId: 'scope-1',
    testId: 'test-1',
    entityRef: 'pkg:npm/leftpad@1.0.0',
    details: { malwarePurl: 'pkg:npm/bad@1.2.3' },
    createdAt: '2026-03-17T12:00:00Z',
    ...overrides,
  };
}

describe('security-alerts.mapper', () => {
  it('maps group and occurrence values', () => {
    const group = createGroup();
    const occurrence = createOccurrence();
    expect(alertGroupValue(group, 'dedupRule')).toContain('TEST');
    expect(alertGroupValue(group, 'occurrences')).toBe('3');
    expect(alertOccurrenceValue(occurrence, 'testId')).toBe('test-1');
    expect(alertOccurrenceValue(occurrence, 'groupId')).toBe('group-1');
  });

  it('maps severity/status classes', () => {
    expect(alertSeverityClass('ERROR')).toContain('error');
    expect(alertSeverityClass('WARN')).toContain('warn');
    expect(alertStatusClass('OPEN')).toContain('open');
    expect(alertStatusClass('ACKNOWLEDGED')).toContain('ack');
  });

  it('detects malware rows and action tooltips', () => {
    const malwareGroup = createGroup();
    const genericGroup = createGroup({ category: 'system', type: 'api.error' });
    const malwareOccurrence = createOccurrence();
    expect(isMalwareAlertGroup(malwareGroup)).toBe(true);
    expect(isMalwareAlertOccurrence(malwareOccurrence)).toBe(true);
    expect(acknowledgeActionTooltip(malwareGroup, true)).toBe('Managed in Explorer');
    expect(acknowledgeActionTooltip(genericGroup, false)).toBe('Admin only');
    expect(closeActionTooltip(genericGroup, true)).toBe('Close');
  });

  it('builds expanded details and safe JSON details', () => {
    const group = createGroup();
    const occurrence = createOccurrence();
    expect(alertGroupExpandedItems(group).some((item) => item.label === 'Group ID')).toBe(true);
    expect(
      alertGroupExpandedItems(group).find((item) => item.label === 'Malware PURL')?.value
    ).toBe('pkg:npm/bad@1.2.3');
    expect(alertGroupExpandedItems(group).some((item) => item.label === 'Entity')).toBe(false);
    expect(alertOccurrenceExpandedItems(occurrence).some((item) => item.label === 'Occurrence ID')).toBe(true);
    expect(alertOccurrenceDetailsJson(occurrence)).toContain('"malwarePurl"');

    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    expect(alertOccurrenceDetailsJson(createOccurrence({ details: circular }))).toBe('{}');
  });

  it('filters and sorts groups by advanced filter state', () => {
    const groupA = createGroup({ id: 'a', title: 'Alpha', occurrences: 1 });
    const groupB = createGroup({ id: 'b', title: 'Beta', occurrences: 5 });
    const rows = applyGroupFiltersAndSort([groupA, groupB], {
      filters: {
        severity: 'ERROR',
        status: '',
        category: '',
        type: '',
        dedupRule: '',
        title: '',
        occurrences: '',
        firstSeenAt: '',
        lastSeenAt: '',
        entityRef: '',
        id: '',
      },
      modes: {
        severity: 'contains',
        status: 'contains',
        category: 'contains',
        type: 'contains',
        dedupRule: 'contains',
        title: 'contains',
        occurrences: 'contains',
        firstSeenAt: 'contains',
        lastSeenAt: 'contains',
        entityRef: 'contains',
        id: 'contains',
      },
      selected: {
        severity: [],
        status: [],
        category: [],
        type: [],
        dedupRule: [],
        title: [],
        occurrences: [],
        firstSeenAt: [],
        lastSeenAt: [],
        entityRef: [],
        id: [],
      },
      sortColumn: 'occurrences',
      sortDirection: 'desc',
    });
    expect(rows.map((row) => row.id)).toEqual(['b', 'a']);
  });

  it('filters and sorts occurrences by advanced filter state', () => {
    const occA = createOccurrence({ id: 'a', title: 'Alpha', occurredAt: '2026-03-10T10:00:00Z' });
    const occB = createOccurrence({ id: 'b', title: 'Beta', occurredAt: '2026-03-12T10:00:00Z' });
    const rows = applyOccurrenceFiltersAndSort([occA, occB], {
      filters: {
        severity: '',
        category: '',
        type: '',
        title: 'beta',
        occurredAt: '',
        entityRef: '',
        testId: '',
        scopeId: '',
        productId: '',
        groupId: '',
        id: '',
      },
      modes: {
        severity: 'contains',
        category: 'contains',
        type: 'contains',
        title: 'contains',
        occurredAt: 'contains',
        entityRef: 'contains',
        testId: 'contains',
        scopeId: 'contains',
        productId: 'contains',
        groupId: 'contains',
        id: 'contains',
      },
      selected: {
        severity: [],
        category: [],
        type: [],
        title: [],
        occurredAt: [],
        entityRef: [],
        testId: [],
        scopeId: [],
        productId: [],
        groupId: [],
        id: [],
      },
      sortColumn: 'occurredAt',
      sortDirection: 'desc',
    });
    expect(rows.map((row) => row.id)).toEqual(['b']);
  });
});
