import { describe, expect, it, vi } from 'vitest';
import { AlertsApi } from '../../data-access/alerts.api';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import {
  acknowledgeAlertGroup,
  buildGroupExplorerNavigation,
  buildOccurrenceExplorerNavigation,
  closeAlertGroup,
  openGroupInExplorer,
  openOccurrenceInExplorer,
} from './security-alerts.operations';

function createGroup(overrides: Partial<AlertGroup> = {}): AlertGroup {
  return {
    id: 'group-1',
    projectId: 'project-1',
    severity: 'ERROR',
    category: 'malware',
    type: 'malware.detected',
    status: 'OPEN',
    groupKey: 'dedup_on:test|test_id:test-1|malware_purl:pkg:npm/mal@1.2.3',
    title: 'Malware detected',
    entityRef: 'pkg:npm/component@1.0.0',
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
    entityRef: 'pkg:npm/component@1.0.0',
    details: { malwarePurl: 'pkg:npm/mal@1.2.3', componentPurl: 'pkg:npm/component@1.0.0' },
    createdAt: '2026-03-17T12:00:00Z',
    ...overrides,
  };
}

describe('security-alerts.operations', () => {
  it('builds group explorer navigation query params', () => {
    const navigation = buildGroupExplorerNavigation(createGroup());
    expect(navigation.queryParams['focusTestId']).toBe('test-1');
    expect(navigation.queryParams['testId']).toBe('test-1');
    expect(navigation.queryParams['malwarePurl']).toBe('pkg:npm/mal@1.2.3');
    expect(navigation.queryParams['ef_malware_summary_ctx_testId']).toBe('test-1');
    expect(navigation.queryParams['ef_malware_summary_ctx_malwarePurl']).toBe('pkg:npm/mal@1.2.3');
  });

  it('builds occurrence explorer navigation only when entity context exists', () => {
    const navigation = buildOccurrenceExplorerNavigation(createOccurrence());
    expect(navigation?.queryParams['focusTestId']).toBe('test-1');
    expect(
      buildOccurrenceExplorerNavigation(
        createOccurrence({ productId: '', scopeId: '', testId: '', entityRef: '', details: {} })
      )
    ).toBeNull();
  });

  it('navigates to explorer for group and occurrence', async () => {
    const navigate = vi.fn().mockResolvedValue(true);
    const router = { navigate } as never;
    await openGroupInExplorer(router, createGroup());
    await openOccurrenceInExplorer(router, createOccurrence());
    expect(navigate).toHaveBeenCalledTimes(2);
    expect(navigate).toHaveBeenNthCalledWith(1, ['/security/explorer'], expect.any(Object));
    expect(navigate).toHaveBeenNthCalledWith(2, ['/security/explorer'], expect.any(Object));
  });

  it('returns false for occurrence navigation when no test/scope/product context exists', async () => {
    const navigate = vi.fn().mockResolvedValue(true);
    const router = { navigate } as never;
    const result = await openOccurrenceInExplorer(
      router,
      createOccurrence({ productId: '', scopeId: '', testId: '', entityRef: '', details: {} })
    );
    expect(result).toBe(false);
    expect(navigate).not.toHaveBeenCalled();
  });

  it('delegates acknowledge and close operations to API', async () => {
    const api = {
      acknowledgeGroup: vi.fn().mockResolvedValue(undefined),
      closeGroup: vi.fn().mockResolvedValue(undefined),
    } as unknown as AlertsApi;
    await acknowledgeAlertGroup(api, 'group-1');
    await closeAlertGroup(api, 'group-1');
    expect(api.acknowledgeGroup).toHaveBeenCalledWith('group-1');
    expect(api.closeGroup).toHaveBeenCalledWith('group-1');
  });
});
