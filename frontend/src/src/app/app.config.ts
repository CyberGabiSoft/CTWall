import {
  APP_INITIALIZER,
  ApplicationConfig,
  ErrorHandler,
  inject,
  provideBrowserGlobalErrorListeners,
  provideZonelessChangeDetection
} from '@angular/core';
import { MAT_FORM_FIELD_DEFAULT_OPTIONS } from '@angular/material/form-field';
import { MAT_SELECT_CONFIG } from '@angular/material/select';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { GlobalErrorHandler } from './core/errors/global-error.handler';
import { provideHttp } from './core/providers/http';
import { ThemeService } from './core/theme/theme.service';
import { MatSelectLiveFilterService } from './core/ui/mat-select-live-filter.service';
import { AuthService } from './features/auth/data-access/auth.service';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZonelessChangeDetection(),
    provideBrowserGlobalErrorListeners(),
    ...provideHttp(),
    { provide: ErrorHandler, useClass: GlobalErrorHandler },
    {
      provide: APP_INITIALIZER,
      multi: true,
      useFactory: () => {
        const auth = inject(AuthService);
        return () => auth.loadSession().catch(() => undefined);
      }
    },
    {
      provide: APP_INITIALIZER,
      multi: true,
      useFactory: () => {
        const theme = inject(ThemeService);
        return () => theme.initialize();
      }
    },
    {
      provide: APP_INITIALIZER,
      multi: true,
      useFactory: () => {
        const selectFilter = inject(MatSelectLiveFilterService);
        return () => selectFilter.init();
      }
    },
    {
      provide: MAT_FORM_FIELD_DEFAULT_OPTIONS,
      useValue: { subscriptSizing: 'dynamic' }
    },
    {
      provide: MAT_SELECT_CONFIG,
      useValue: { typeaheadDebounceInterval: 120 }
    },
    provideRouter(routes)
  ]
};
