import { describe, expect, it, vi } from 'vitest';
import { AlertsApi, AlertGroupsListQuery, AlertOccurrencesListQuery } from '../../data-access/alerts.api';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import { exportAllGroups, exportAllOccurrences } from './security-alerts.export';

function group(id: string, occurrences = 1): AlertGroup {
  return {
    id,
    projectId: 'project-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    status: 'OPEN',
    groupKey: 'dedup_on:test|test_id:test-1',
    title: `Group ${id}`,
    entityRef: null,
    occurrences,
    firstSeenAt: '2026-03-17T10:00:00Z',
    lastSeenAt: '2026-03-17T11:00:00Z',
    createdAt: '2026-03-17T10:00:00Z',
    updatedAt: '2026-03-17T11:00:00Z',
  };
}

function occurrence(id: string): AlertOccurrence {
  return {
    id,
    projectId: 'project-1',
    groupId: 'group-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    title: `Occurrence ${id}`,
    occurredAt: '2026-03-17T12:00:00Z',
    productId: 'product-1',
    scopeId: 'scope-1',
    testId: 'test-1',
    entityRef: 'pkg:npm/component@1.0.0',
    details: {},
    createdAt: '2026-03-17T12:00:00Z',
  };
}

describe('security-alerts.export', () => {
  it('exports groups across pages and applies filter/sort', async () => {
    const api = {
      listGroups: vi
        .fn()
        .mockResolvedValueOnce({ items: [group('a', 1)], totalPages: 2 })
        .mockResolvedValueOnce({ items: [group('b', 5)], totalPages: 2 }),
    } as unknown as AlertsApi;
    const query: AlertGroupsListQuery = { page: 1, pageSize: 50 };
    const rows = await exportAllGroups(api, query, {
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
    expect(api.listGroups).toHaveBeenCalledTimes(2);
    expect(rows.map((row) => row.id)).toEqual(['b', 'a']);
  });

  it('exports occurrences across pages and applies filter/sort', async () => {
    const api = {
      listOccurrences: vi
        .fn()
        .mockResolvedValueOnce({ items: [occurrence('a')], totalPages: 2 })
        .mockResolvedValueOnce({ items: [occurrence('b')], totalPages: 2 }),
    } as unknown as AlertsApi;
    const query: AlertOccurrencesListQuery = { page: 1, pageSize: 50 };
    const rows = await exportAllOccurrences(api, query, {
      filters: {
        severity: '',
        category: '',
        type: '',
        title: 'Occurrence b',
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
    expect(api.listOccurrences).toHaveBeenCalledTimes(2);
    expect(rows.map((row) => row.id)).toEqual(['b']);
  });
});
