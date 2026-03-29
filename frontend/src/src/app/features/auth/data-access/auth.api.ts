import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { AuthUser } from '../auth.types';

export interface LoginPayload {
  email: string;
  password: string;
}

export interface ChangePasswordPayload {
  currentPassword: string;
  newPassword: string;
}

@Injectable({ providedIn: 'root' })
export class AuthApi {
  private readonly http = inject(HttpClient);

  async login(payload: LoginPayload): Promise<void> {
    await firstValueFrom(this.http.post<void>('/auth/login', payload));
  }

  async refresh(): Promise<void> {
    await firstValueFrom(this.http.post<void>('/auth/refresh', {}));
  }

  async logout(): Promise<void> {
    await firstValueFrom(this.http.post<void>('/auth/logout', {}));
  }

  async changePassword(payload: ChangePasswordPayload): Promise<void> {
    await firstValueFrom(this.http.post<void>('/auth/change-password', payload));
  }

  async me(): Promise<AuthUser> {
    return firstValueFrom(this.http.get<AuthUser>('/auth/me'));
  }
}
