import {
  HttpContextToken,
  HttpEventType,
  HttpInterceptorFn
} from '@angular/common/http';
import { inject } from '@angular/core';
import { MatSnackBar } from '@angular/material/snack-bar';
import { tap } from 'rxjs';

export const SKIP_SUCCESS_FEEDBACK = new HttpContextToken<boolean>(() => false);

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

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
  return (
    path.includes('/auth/login') ||
    path.includes('/auth/logout') ||
    path.includes('/auth/refresh') ||
    path.includes('/auth/me')
  );
};

const isApiRequest = (url: string): boolean => {
  const path = normalizePath(url);
  return path.includes('/api/v1/');
};

const isUserPasswordResetEndpoint = (url: string): boolean => {
  const path = normalizePath(url);
  return /^\/?api\/v1\/users\/[^/]+\/password$/i.test(path);
};

const successMessageForMethod = (method: string): string => {
  switch (method.toUpperCase()) {
    case 'POST':
      return 'Added successfully.';
    case 'DELETE':
      return 'Deleted successfully.';
    case 'PUT':
    case 'PATCH':
      return 'Saved successfully.';
    default:
      return 'Success.';
  }
};

const successMessageForRequest = (method: string, url: string): string => {
  if (method.toUpperCase() === 'POST' && isUserPasswordResetEndpoint(url)) {
    return 'Password changed.';
  }
  return successMessageForMethod(method);
};

export const successFeedbackInterceptor: HttpInterceptorFn = (req, next) => {
  const method = req.method.toUpperCase();
  const eligible =
    MUTATION_METHODS.has(method) &&
    isApiRequest(req.url) &&
    !isAuthEndpoint(req.url) &&
    !req.context.get(SKIP_SUCCESS_FEEDBACK);

  if (!eligible) {
    return next(req);
  }

  const snackBar = inject(MatSnackBar);
  const message = successMessageForRequest(method, req.url);

  return next(req).pipe(
    tap((event) => {
      if (event.type !== HttpEventType.Response) {
        return;
      }
      snackBar.open(message, 'Close', {
        duration: 3000,
        panelClass: ['ctw-snackbar-success']
      });
    })
  );
};
