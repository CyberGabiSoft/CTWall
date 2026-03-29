import { HttpErrorResponse } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { AuthStore } from '../auth.store';
import { AuthUser } from '../auth.types';
import { AuthApi, ChangePasswordPayload, LoginPayload } from './auth.api';
import { ProjectContextService } from '../../projects/data-access/project-context.service';

const isAuthError = (error: unknown): boolean => {
  return error instanceof HttpErrorResponse && (error.status === 401 || error.status === 403);
};

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly store = inject(AuthStore);
  private readonly api = inject(AuthApi);
  private readonly projects = inject(ProjectContextService);

  async loadSession(): Promise<void> {
    if (this.store.status() !== 'unknown') {
      return;
    }

    try {
      const user = await this.api.me();
      this.store.setUser(user);
    } catch (error) {
      if (!isAuthError(error)) {
        throw error;
      }
      await this.refreshSession();
    }
  }

  async login(payload: LoginPayload): Promise<AuthUser> {
    await this.api.login(payload);
    const user = await this.api.me();
    this.store.setUser(user);
    return user;
  }

  logout(): void {
    this.store.clear();
    this.projects.clear();
  }

  async performLogout(): Promise<void> {
    try {
      await this.api.logout();
    } finally {
      this.store.clear();
      this.projects.clear();
    }
  }

  async changePassword(payload: ChangePasswordPayload): Promise<void> {
    await this.api.changePassword(payload);
  }

  async refreshSession(): Promise<boolean> {
    try {
      await this.api.refresh();
      const user = await this.api.me();
      this.store.setUser(user);
      return true;
    } catch (error) {
      if (!isAuthError(error)) {
        throw error;
      }
      this.store.clear();
      return false;
    }
  }
}
