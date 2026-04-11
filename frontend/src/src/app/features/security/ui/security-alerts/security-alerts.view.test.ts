import { describe, expect, it } from 'vitest';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import {
  buildGroupAdvancedFields,
  buildGroupFilterOptions,
  buildOccurrenceAdvancedFields,
  buildOccurrenceFilterOptions,
  groupValueForTable,
  occurrenceValueForTable,
} from './security-alerts.view';

function createGroup(overrides: Partial<AlertGroup> = {}): AlertGroup {
  return {
    id: 'group-1',
    projectId: 'project-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    status: 'OPEN',
    groupKey: 'dedup_on:test|test_id:test-1|detect_mode:purl_version_smart|malware_purl:pkg:npm/bad@1.2.3',
    title: 'Malware detected',
    entityRef: 'pkg:npm/component@1.0.0',
    occurrences: 2,
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
    entityRef: 'pkg:npm/component@1.0.0',
    details: { matchType: 'CONTAINS_PREFIX' },
    createdAt: '2026-03-17T12:00:00Z',
    ...overrides,
  };
}

describe('security-alerts.view', () => {
  it('builds group options and advanced fields', () => {
    const options = buildGroupFilterOptions([createGroup()]);
    expect(options.severity).toEqual(['ERROR']);
    expect(options.status).toEqual(['CLOSED', 'OPEN']);
    const fields = buildGroupAdvancedFields(
      {
        severity: 'contains',
        status: 'contains',
        category: 'contains',
        type: 'contains',
        detectionMode: 'contains',
        detectionData: 'contains',
        dedupRule: 'contains',
        title: 'contains',
        occurrences: 'contains',
        firstSeenAt: 'contains',
        lastSeenAt: 'contains',
        entityRef: 'contains',
        id: 'contains',
      },
      {
        severity: '',
        status: '',
        category: '',
        type: '',
        detectionMode: '',
        detectionData: '',
        dedupRule: '',
        title: '',
        occurrences: '',
        firstSeenAt: '',
        lastSeenAt: '',
        entityRef: '',
        id: '',
      },
      {
        severity: [],
        status: [],
        category: [],
        type: [],
        detectionMode: [],
        detectionData: [],
        dedupRule: [],
        title: [],
        occurrences: [],
        firstSeenAt: [],
        lastSeenAt: [],
        entityRef: [],
        id: [],
      },
      options
    );
    expect(fields.find((field) => field.key === 'severity')?.label).toBe('Severity');
    expect(fields).toHaveLength(13);
  });

  it('builds occurrence options and advanced fields', () => {
    const options = buildOccurrenceFilterOptions([createOccurrence()]);
    expect(options.groupId).toEqual(['group-1']);
    const fields = buildOccurrenceAdvancedFields(
      {
        severity: 'contains',
        category: 'contains',
        type: 'contains',
        detectionMode: 'contains',
        detectionData: 'contains',
        title: 'contains',
        occurredAt: 'contains',
        entityRef: 'contains',
        testId: 'contains',
        scopeId: 'contains',
        productId: 'contains',
        groupId: 'contains',
        id: 'contains',
      },
      {
        severity: '',
        category: '',
        type: '',
        detectionMode: '',
        detectionData: '',
        title: '',
        occurredAt: '',
        entityRef: '',
        testId: '',
        scopeId: '',
        productId: '',
        groupId: '',
        id: '',
      },
      {
        severity: [],
        category: [],
        type: [],
        detectionMode: [],
        detectionData: [],
        title: [],
        occurredAt: [],
        entityRef: [],
        testId: [],
        scopeId: [],
        productId: [],
        groupId: [],
        id: [],
      },
      options
    );
    expect(fields.find((field) => field.key === 'groupId')?.label).toBe('Group ID');
    expect(fields).toHaveLength(13);
  });

  it('returns safe table value for unknown keys', () => {
    expect(groupValueForTable(createGroup(), 'unknown')).toBe('-');
    expect(occurrenceValueForTable(createOccurrence(), 'unknown')).toBe('-');
  });

  it('resolves detail column values when detail columns are selected', () => {
    expect(groupValueForTable(createGroup(), '__detail__:malware_purl')).toBe('pkg:npm/bad@1.2.3');
    expect(occurrenceValueForTable(createOccurrence(), '__detail__:match_type')).toBe('CONTAINS_PREFIX');
  });
});
