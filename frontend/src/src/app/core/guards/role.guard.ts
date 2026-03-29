import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthStore } from '../../features/auth/auth.store';
import { UserRole } from '../../features/auth/auth.types';

export const roleGuard = (requiredRole: UserRole): CanActivateFn => {
  return (_route, state) => {
    const auth = inject(AuthStore);
    const router = inject(Router);

    if (auth.hasRole(requiredRole)) {
      return true;
    }

    return router.createUrlTree(['/forbidden'], {
      queryParams: { redirect: state.url }
    });
  };
};
