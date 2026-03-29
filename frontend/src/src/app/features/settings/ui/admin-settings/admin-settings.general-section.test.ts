import { describe, expect, it } from 'vitest';
import { signal } from '@angular/core';
import { SettingsGeneralResponse } from '../../data-access/settings.types';
import { AdminSettingsGeneralSectionController } from './admin-settings.general-section';

const makeGeneral = (
  overrides: Partial<SettingsGeneralResponse> = {},
): SettingsGeneralResponse => ({
  readOnly: true,
  configPath: '/etc/ctwall/config.yaml',
  generatedAt: '2026-03-19T12:00:00Z',
  config: { server: { port: 8080 } },
  sources: {},
  ...overrides,
});

describe('AdminSettingsGeneralSectionController', () => {
  it('formats default values from general payload', () => {
    const payload = signal<SettingsGeneralResponse | null>(makeGeneral());
    const controller = new AdminSettingsGeneralSectionController(() => payload());

    expect(controller.readOnlyLabel()).toBe('Yes');
    expect(controller.configPath()).toBe('/etc/ctwall/config.yaml');
    expect(controller.generatedAt()).toBe('2026-03-19T12:00:00Z');
    expect(controller.configJson()).toContain('"port": 8080');
  });

  it('returns safe defaults when payload is empty', () => {
    const payload = signal<SettingsGeneralResponse | null>(null);
    const controller = new AdminSettingsGeneralSectionController(() => payload());

    expect(controller.readOnlyLabel()).toBe('No');
    expect(controller.configPath()).toBe('-');
    expect(controller.generatedAt()).toBeNull();
    expect(controller.configJson()).toContain('{}');
  });
});
