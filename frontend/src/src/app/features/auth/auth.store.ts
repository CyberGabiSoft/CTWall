import { computed, Injectable, signal } from '@angular/core';
import { AuthStatus, AuthUser, UserRole } from './auth.types';

const roleRank = (role: UserRole): number => {
  switch (role) {
    case 'NONE':
      return 0;
    case 'READER':
      return 1;
    case 'WRITER':
      return 2;
    case 'ADMIN':
      return 3;
    default:
      return 0;
  }
};

@Injectable({ providedIn: 'root' })
export class AuthStore {
  private readonly statusState = signal<AuthStatus>('unknown');
  private readonly userState = signal<AuthUser | null>(null);

  readonly status = computed(() => this.statusState());
  readonly user = computed(() => this.userState());
  readonly isAuthenticated = computed(() => this.statusState() === 'authenticated');

  setUser(user: AuthUser): void {
    this.userState.set(user);
    this.statusState.set('authenticated');
  }

  clear(): void {
    this.userState.set(null);
    this.statusState.set('anonymous');
  }

  markUnknown(): void {
    this.statusState.set('unknown');
  }

  hasRole(required: UserRole): boolean {
    const current = this.userState();
    if (!current) {
      return false;
    }
    return roleRank(current.role) >= roleRank(required);
  }
}
