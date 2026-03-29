import { CanActivateFn } from '@angular/router';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthStore } from '../../features/auth/auth.store';
import { AuthService } from '../../features/auth/data-access/auth.service';

export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthStore);
  const authService = inject(AuthService);
  const router = inject(Router);

  if (auth.status() === 'unknown') {
    try {
      await authService.loadSession();
    } catch {
      return router.createUrlTree(['/login'], {
        queryParams: { redirect: state.url }
      });
    }
  }

  if (auth.isAuthenticated()) {
    return true;
  }

  return router.createUrlTree(['/login'], {
    queryParams: { redirect: state.url }
  });
};
