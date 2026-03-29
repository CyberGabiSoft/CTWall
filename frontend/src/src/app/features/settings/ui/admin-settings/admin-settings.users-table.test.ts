import { describe, expect, it } from 'vitest';
import { signal } from '@angular/core';
import { AdminSettingsUsersTableController } from './admin-settings.users-table';
import { SettingsUser } from '../../data-access/settings.types';

const makeUser = (overrides: Partial<SettingsUser> = {}): SettingsUser => ({
  id: 'user-1',
  email: 'user@test.com',
  nickname: 'user',
  fullName: 'User Test',
  role: 'READER',
  accountType: 'USER',
  createdAt: '2026-03-19T10:00:00Z',
  updatedAt: '2026-03-19T10:00:00Z',
  ...overrides,
});

describe('AdminSettingsUsersTableController', () => {
  it('filters rows by email using contains mode', () => {
    const users = signal<SettingsUser[]>([
      makeUser({ email: 'admin@test.com' }),
      makeUser({ id: 'user-2', email: 'ops@test.com' }),
    ]);
    const controller = new AdminSettingsUsersTableController(() => users());

    controller.setFilterValue('email', 'admin');

    expect(controller.rows()).toHaveLength(1);
    expect(controller.rows()[0]?.email).toBe('admin@test.com');
  });

  it('recognizes service accounts', () => {
    const users = signal<SettingsUser[]>([
      makeUser({ accountType: 'SERVICE_ACCOUNT' }),
    ]);
    const controller = new AdminSettingsUsersTableController(() => users());

    expect(controller.isServiceAccount(users()[0]!)).toBe(true);
  });
});
