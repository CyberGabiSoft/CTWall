import { Routes } from '@angular/router';
import { MainLayoutComponent } from './core/layout/main-layout/main-layout.component';
import { authGuard } from './core/guards/auth.guard';
import { roleGuard } from './core/guards/role.guard';

export const routes: Routes = [
  {
    path: 'login',
    loadComponent: () =>
      import('./features/auth/ui/login/login.component').then((m) => m.LoginComponent),
  },
  {
    path: '',
    component: MainLayoutComponent,
    canActivate: [authGuard],
    children: [
      {
        path: 'dashboard',
        loadComponent: () =>
          import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
      },
      {
        path: 'events',
        loadComponent: () =>
          import('./features/events/ui/events-page.component').then((m) => m.EventsPageComponent),
      },
      {
        path: 'admin/projects',
        canActivate: [roleGuard('ADMIN')],
        loadComponent: () =>
          import('./features/projects/ui/manage-projects/manage-projects.component').then(
            (m) => m.ManageProjectsComponent,
          ),
      },
      {
        path: 'admin/settings',
        canActivate: [roleGuard('ADMIN')],
        children: [
          {
            path: 'general',
            loadComponent: () =>
              import('./features/settings/ui/admin-settings/admin-settings.component').then(
                (m) => m.AdminSettingsComponent,
              ),
            data: { section: 'general' },
          },
          {
            path: 'connectors',
            loadComponent: () =>
              import('./features/settings/ui/admin-settings/admin-settings.component').then(
                (m) => m.AdminSettingsComponent,
              ),
            data: { section: 'connectors' },
          },
          {
            path: 'users',
            loadComponent: () =>
              import('./features/settings/ui/admin-settings/admin-settings.component').then(
                (m) => m.AdminSettingsComponent,
              ),
            data: { section: 'users' },
          },
          { path: '', redirectTo: 'general', pathMatch: 'full' },
        ],
      },
      {
        path: 'data/import',
        loadComponent: () =>
          import('./features/ingest/ui/ingest-shell/ingest.component').then(
            (m) => m.IngestComponent,
          ),
      },
      {
        path: 'data/graph',
        loadComponent: () =>
          import('./features/data/ui/data-graph/data-graph.component').then(
            (m) => m.DataGraphComponent,
          ),
      },
      {
        path: 'data/user-groups',
        loadComponent: () =>
          import('./features/data/ui/data-identity/data-identity.component').then(
            (m) => m.DataIdentityComponent,
          ),
      },
      { path: 'data/identity', redirectTo: 'data/user-groups', pathMatch: 'full' },
      {
        path: 'data',
        pathMatch: 'full',
        loadComponent: () =>
          import('./features/data/ui/data-shell/data.component').then((m) => m.DataComponent),
      },
      {
        path: 'search/components',
        loadComponent: () =>
          import('./features/search/ui/component-occurrences-search.component').then(
            (m) => m.ComponentOccurrencesSearchComponent,
          ),
      },
      {
        path: 'forbidden',
        loadComponent: () =>
          import('./features/auth/ui/forbidden/forbidden.component').then(
            (m) => m.ForbiddenComponent,
          ),
      },
      {
        path: 'account/change-password',
        loadComponent: () =>
          import('./features/auth/ui/change-password/change-password.component').then(
            (m) => m.ChangePasswordComponent,
          ),
      },
      {
        path: 'security',
        loadComponent: () =>
          import('./features/security/ui/security-shell/security-shell.component').then(
            (m) => m.SecurityShellComponent,
          ),
        children: [
          {
            path: 'posture',
            loadComponent: () =>
              import('./features/security/ui/security-posture/security-posture.component').then(
                (m) => m.SecurityPostureComponent,
              ),
          },
          {
            path: 'sources',
            loadComponent: () =>
              import('./features/security/ui/security-sources/security-sources.component').then(
                (m) => m.SecuritySourcesComponent,
              ),
          },
          {
            path: 'alerts',
            loadComponent: () =>
              import('./features/security/ui/security-alerts/security-alerts.component').then(
                (m) => m.SecurityAlertsComponent,
              ),
          },
          {
            path: 'explorer',
            loadComponent: () =>
              import('./features/security/ui/security-malware/security-malware-shell.component').then(
                (m) => m.SecurityMalwareShellComponent,
              ),
            children: [
              {
                path: '',
                loadComponent: () =>
                  import('./features/security/ui/security-malware/security-malware-overview.component').then(
                    (m) => m.SecurityMalwareOverviewComponent,
                  ),
              },
              {
                path: 'runs',
                loadComponent: () =>
                  import('./features/security/ui/security-malware/security-malware-runs.component').then(
                    (m) => m.SecurityMalwareRunsComponent,
                  ),
              },
              {
                path: 'config',
                redirectTo: 'runs',
                pathMatch: 'full',
              },
              {
                path: 'tests/:testId',
                loadComponent: () =>
                  import('./features/security/ui/security-malware/security-malware-detail.component').then(
                    (m) => m.SecurityMalwareDetailComponent,
                  ),
              },
            ],
          },
          { path: '', redirectTo: 'posture', pathMatch: 'full' },
        ],
      },
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
    ],
  },
];
