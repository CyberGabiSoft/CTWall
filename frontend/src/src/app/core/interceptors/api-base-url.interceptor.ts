import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { API_BASE_URL, API_PREFIX } from '../http/http.tokens';

const isAbsoluteUrl = (value: string): boolean => /^https?:\/\//i.test(value);

export const apiBaseUrlInterceptor: HttpInterceptorFn = (req, next) => {
  if (isAbsoluteUrl(req.url)) {
    return next(req);
  }

  const baseUrl = inject(API_BASE_URL);
  const prefix = inject(API_PREFIX);

  if (req.url.startsWith(prefix) || req.url.startsWith(`/` + prefix.replace(/^\//, ''))) {
    return next(req);
  }

  if (req.url.startsWith('/assets') || req.url.startsWith('assets/')) {
    return next(req);
  }

  const trimmed = req.url.replace(/^\/+/, '');
  const normalizedBase = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
  const normalizedPrefix = prefix.startsWith('/') ? prefix : `/${prefix}`;
  const url = `${normalizedBase}${normalizedPrefix}/${trimmed}`;

  return next(req.clone({ url }));
};
