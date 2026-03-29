import '@angular/compiler';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { SettingsApi } from './settings.api';

const createApi = () => {
  const patch = vi.fn();
  const post = vi.fn();
  const del = vi.fn();
  const get = vi.fn();
  const api = Object.create(SettingsApi.prototype) as SettingsApi;
  (api as unknown as { http: { patch: typeof patch; post: typeof post; delete: typeof del; get: typeof get } }).http = {
    patch,
    post,
    delete: del,
    get
  };
  return { api, patch, post, del, get };
};

describe('SettingsApi flow tests', () => {
  it('executes edit user flow endpoint: update user', async () => {
    const { api, patch } = createApi();

    patch.mockReturnValue(of({ id: 'u-1', email: 'edited@example.com' }));
    const update = await api.updateUser('u-1', {
      role: 'ADMIN',
      accountType: 'USER',
      nickname: 'edited-user',
      fullName: 'Edited User'
    });
    expect(update).toMatchObject({ id: 'u-1', email: 'edited@example.com' });
    expect(patch).toHaveBeenCalledWith('/users/u-1', {
      role: 'ADMIN',
      accountType: 'USER',
      nickname: 'edited-user',
      fullName: 'Edited User'
    });
  });

  it('sends token options when creating service account token', async () => {
    const { api, post } = createApi();
    post.mockReturnValue(
      of({
        tokenId: 'token-1',
        token: 'raw-token',
        name: 'service-main',
        expiresAt: '2026-12-31T10:00:00Z',
        createdAt: '2026-02-11T12:00:00Z'
      })
    );

    const response = await api.createUserToken('svc-1', {
      name: 'service-main',
      expiresAt: '2026-12-31T10:00:00Z'
    });
    expect(response).toMatchObject({ tokenId: 'token-1', name: 'service-main' });
    expect(post).toHaveBeenCalledWith('/users/svc-1/tokens', {
      name: 'service-main',
      expiresAt: '2026-12-31T10:00:00Z'
    });
  });

  it('posts admin password reset payload for a user', async () => {
    const { api, post } = createApi();
    post.mockReturnValue(of(undefined));

    await api.resetUserPassword('u-44', { newPassword: 'An0ther!Passw0rd' });

    expect(post).toHaveBeenCalledWith('/users/u-44/password', {
      newPassword: 'An0ther!Passw0rd'
    });
  });

  it('sends smtp recipient when testing connector', async () => {
    const { api, post } = createApi();
    post.mockReturnValue(
      of({
        type: 'smtp',
        status: 'PASSED',
        message: 'SMTP test email sent successfully.',
        testedAt: '2026-02-20T19:57:14.47955658Z'
      })
    );

    const response = await api.testConnector('smtp', { toEmail: 'smtp-test@local.test' });
    expect(response).toMatchObject({ type: 'smtp', status: 'PASSED' });
    expect(post).toHaveBeenCalledWith('/admin/connectors/smtp/test', { toEmail: 'smtp-test@local.test' }, expect.any(Object));
  });
});
