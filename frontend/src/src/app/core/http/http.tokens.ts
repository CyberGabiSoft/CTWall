import { InjectionToken } from '@angular/core';

export const API_BASE_URL = new InjectionToken<string>('API_BASE_URL', {
  factory: () => ''
});

export const API_PREFIX = new InjectionToken<string>('API_PREFIX', {
  factory: () => '/api/v1'
});
