import { describe, expect, it } from 'vitest';
import { AuthStore } from './auth.store';

const user = {
  id: 'user-1',
  email: 'user@example.com',
  nickname: 'jane',
  role: 'WRITER' as const,
  accountType: 'USER' as const,
  fullName: 'Jane Doe'
};

describe('AuthStore', () => {
  it('starts in unknown state', () => {
    const store = new AuthStore();
    expect(store.status()).toBe('unknown');
    expect(store.isAuthenticated()).toBe(false);
    expect(store.user()).toBeNull();
  });

  it('sets user and marks authenticated', () => {
    const store = new AuthStore();
    store.setUser(user);
    expect(store.status()).toBe('authenticated');
    expect(store.isAuthenticated()).toBe(true);
    expect(store.user()).toMatchObject({ email: user.email });
  });

  it('clears user and marks anonymous', () => {
    const store = new AuthStore();
    store.setUser(user);
    store.clear();
    expect(store.status()).toBe('anonymous');
    expect(store.isAuthenticated()).toBe(false);
    expect(store.user()).toBeNull();
  });

  it('checks role hierarchy', () => {
    const store = new AuthStore();
    store.setUser(user);
    expect(store.hasRole('READER')).toBe(true);
    expect(store.hasRole('WRITER')).toBe(true);
    expect(store.hasRole('ADMIN')).toBe(false);
  });

  it('treats NONE as no-access base role', () => {
    const store = new AuthStore();
    store.setUser({ ...user, role: 'NONE' });
    expect(store.hasRole('NONE')).toBe(true);
    expect(store.hasRole('READER')).toBe(false);
  });
});
