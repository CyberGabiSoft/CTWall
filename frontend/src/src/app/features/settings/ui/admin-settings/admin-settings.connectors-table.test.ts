import { describe, expect, it } from 'vitest';
import { signal } from '@angular/core';
import { AdminSettingsConnectorsTableController } from './admin-settings.connectors-table';
import { AdminConnector } from '../../data-access/settings.types';

const makeConnector = (overrides: Partial<AdminConnector> = {}): AdminConnector => ({
  type: 'jira',
  scopeType: 'PROJECT',
  enabled: true,
  configured: true,
  config: {},
  updatedAt: '2026-03-19T10:00:00Z',
  lastTestStatus: 'PASSED',
  lastTestAt: '2026-03-19T10:00:00Z',
  ...overrides,
});

describe('AdminSettingsConnectorsTableController', () => {
  it('filters rows by connector type in contains mode', () => {
    const connectors = signal<AdminConnector[]>([
      makeConnector({ type: 'jira' }),
      makeConnector({ type: 'alertmanager_external' }),
    ]);
    const controller = new AdminSettingsConnectorsTableController(() => connectors());

    controller.setFilterValue('type', 'jira');

    expect(controller.rows()).toHaveLength(1);
    expect(controller.rows()[0]?.type).toBe('jira');
  });

  it('sorts by updatedAt descending', () => {
    const connectors = signal<AdminConnector[]>([
      makeConnector({ type: 'jira', updatedAt: '2026-03-18T10:00:00Z' }),
      makeConnector({ type: 'alertmanager_external', updatedAt: '2026-03-19T10:00:00Z' }),
    ]);
    const controller = new AdminSettingsConnectorsTableController(() => connectors());

    controller.toggleSort('updatedAt');
    controller.toggleSort('updatedAt');

    expect(controller.rows()[0]?.type).toBe('alertmanager_external');
    expect(controller.rows()[1]?.type).toBe('jira');
  });
});
