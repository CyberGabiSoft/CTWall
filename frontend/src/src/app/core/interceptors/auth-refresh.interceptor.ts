import {
  HttpContextToken,
  HttpErrorResponse,
  HttpInterceptorFn
} from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AuthService } from '../../features/auth/data-access/auth.service';

const AUTH_RETRY = new HttpContextToken<boolean>(() => false);

let refreshPromise: Promise<boolean> | null = null;

const normalizePath = (url: string): string => {
  if (/^https?:\/\//i.test(url)) {
    try {
      return new URL(url).pathname;
    } catch {
      return url;
    }
  }
  return url;
};

const isAuthEndpoint = (url: string): boolean => {
  const path = normalizePath(url);
  return path.includes('/auth/login') || path.includes('/auth/refresh') || path.includes('/auth/me');
};

const refreshOnce = (auth: AuthService): Promise<boolean> => {
  if (!refreshPromise) {
    refreshPromise = auth.refreshSession().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
};

export const authRefreshInterceptor: HttpInterceptorFn = (req, next) => {
  if (isAuthEndpoint(req.url)) {
    return next(req);
  }

  const auth = inject(AuthService);
  const router = inject(Router);

  return next(req).pipe(
    catchError((error: unknown) => {
      if (!(error instanceof HttpErrorResponse) || error.status !== 401) {
        return throwError(() => error);
      }

      if (req.context.get(AUTH_RETRY)) {
        return throwError(() => error);
      }

      return from(refreshOnce(auth)).pipe(
        switchMap((ok) => {
          if (!ok) {
            auth.logout();
            router.navigate(['/login'], { queryParams: { redirect: router.url } });
            return throwError(() => error);
          }
          const retryReq = req.clone({ context: req.context.set(AUTH_RETRY, true) });
          return next(retryReq);
        }),
        catchError((refreshError) => {
          auth.logout();
          router.navigate(['/login'], { queryParams: { redirect: router.url } });
          return throwError(() => refreshError);
        })
      );
    })
  );
};
