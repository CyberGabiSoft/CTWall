import { provideHttpClient, withInterceptors, withXsrfConfiguration } from '@angular/common/http';
import { EnvironmentProviders, Provider } from '@angular/core';
import { apiBaseUrlInterceptor } from '../interceptors/api-base-url.interceptor';
import { authRefreshInterceptor } from '../interceptors/auth-refresh.interceptor';
import { credentialsInterceptor } from '../interceptors/credentials.interceptor';
import { projectHeaderInterceptor } from '../interceptors/project-header.interceptor';
import { successFeedbackInterceptor } from '../interceptors/success-feedback.interceptor';
import { API_BASE_URL, API_PREFIX } from '../http/http.tokens';

export const provideHttp = (): Array<Provider | EnvironmentProviders> => [
  provideHttpClient(
    withXsrfConfiguration({
      cookieName: '__Host-XSRF-TOKEN',
      headerName: 'X-XSRF-TOKEN'
    }),
    withInterceptors([
      apiBaseUrlInterceptor,
      credentialsInterceptor,
      projectHeaderInterceptor,
      authRefreshInterceptor,
      successFeedbackInterceptor
    ])
  ),
  { provide: API_BASE_URL, useValue: '' },
  { provide: API_PREFIX, useValue: '/api/v1' }
];
