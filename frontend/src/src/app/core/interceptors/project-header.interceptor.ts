import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { ProjectContextService } from '../../features/projects/data-access/project-context.service';

const isAbsoluteUrl = (value: string): boolean => /^https?:\/\//i.test(value);

const normalizePath = (url: string): string => {
  if (!isAbsoluteUrl(url)) {
    return url;
  }
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
};

const shouldSkip = (url: string): boolean => {
  const path = normalizePath(url);
  return (
    path.includes('/auth/login') ||
    path.includes('/auth/refresh') ||
    path.includes('/auth/logout') ||
    path.includes('/auth/me') ||
    path.startsWith('/assets') ||
    path.startsWith('assets/')
  );
};

export const projectHeaderInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.headers.has('X-Project-ID') || shouldSkip(req.url)) {
    return next(req);
  }

  const projectContext = inject(ProjectContextService);
  const selectedProjectId = projectContext.selectedProjectId();
  if (!selectedProjectId) {
    return next(req);
  }

  return next(
    req.clone({
      setHeaders: {
        'X-Project-ID': selectedProjectId
      }
    })
  );
};
