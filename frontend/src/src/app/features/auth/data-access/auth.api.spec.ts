import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AuthApi } from './auth.api';
import { provideHttp } from '../../../core/providers/http';

describe('AuthApi (TestBed)', () => {
  it('posts change password', async () => {
    await TestBed.configureTestingModule({
      providers: [AuthApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(AuthApi);
    const http = TestBed.inject(HttpTestingController);

    const payload = { currentPassword: 'OldPass1!', newPassword: 'NewPass1!' };
    const promise = api.changePassword(payload);
    const req = http.expectOne('/api/v1/auth/change-password');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(payload);
    req.flush(null);

    await expect(promise).resolves.toBeUndefined();
    http.verify();
  });

  it('posts logout', async () => {
    await TestBed.configureTestingModule({
      providers: [AuthApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(AuthApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.logout();
    const req = http.expectOne('/api/v1/auth/logout');
    expect(req.request.method).toBe('POST');
    req.flush(null);

    await expect(promise).resolves.toBeUndefined();
    http.verify();
  });
});
