import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { API_PREFIX } from '../http/http.tokens';

const shouldAttachCredentials = (url: string, prefix: string): boolean => {
  if (/^https?:\/\//i.test(url)) {
    return url.includes(prefix);
  }

  if (url.startsWith(prefix) || url.startsWith(`/${prefix.replace(/^\//, '')}`)) {
    return true;
  }

  return !url.startsWith('/assets') && !url.startsWith('assets/');
};

export const credentialsInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.withCredentials) {
    return next(req);
  }

  const prefix = inject(API_PREFIX);
  if (!shouldAttachCredentials(req.url, prefix)) {
    return next(req);
  }

  return next(req.clone({ withCredentials: true }));
};
