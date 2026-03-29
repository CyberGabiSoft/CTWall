import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  computed,
  inject,
  signal,
} from '@angular/core';
import { NavigationEnd, Router, RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';

import { NgOptimizedImage } from '@angular/common';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatMenuModule } from '@angular/material/menu';
import { MatButtonModule } from '@angular/material/button';
import { MatBadgeModule } from '@angular/material/badge';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { ErrorBannerComponent } from '../../ui/error-banner/error-banner.component';
import { AuthService } from '../../../features/auth/data-access/auth.service';
import { AuthStore } from '../../../features/auth/auth.store';
import { ThemeService } from '../../theme/theme.service';
import {
  Activity,
  Bell,
  Bug,
  Copyright,
  ChevronLeft,
  ChevronRight,
  Database,
  Folder,
  LayoutDashboard,
  List,
  LucideAngularModule,
  Moon,
  Search,
  Settings,
  Share2,
  ShieldCheck,
  Sun,
  TriangleAlert,
  Upload,
  User,
  Users,
  X,
} from 'lucide-angular';
import { filter, fromEvent, interval } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { EventsApi } from '../../../features/events/data-access/events.api';
import { ProjectContextService } from '../../../features/projects/data-access/project-context.service';
import { AppVersionService } from '../../http/app-version.service';

@Component({
  selector: 'app-main-layout',
  imports: [
    NgOptimizedImage,
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    MatToolbarModule,
    MatMenuModule,
    MatButtonModule,
    MatBadgeModule,
    MatTooltipModule,
    MatFormFieldModule,
    MatSelectModule,
    ErrorBannerComponent,
    LucideAngularModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './main-layout.component.html',
  styleUrl: './main-layout.component.scss',
})
export class MainLayoutComponent {
  readonly LayoutDashboard = LayoutDashboard;
  readonly Database = Database;
  readonly Folder = Folder;
  readonly List = List;
  readonly Upload = Upload;
  readonly Users = Users;
  readonly ShieldCheck = ShieldCheck;
  readonly Activity = Activity;
  readonly TriangleAlert = TriangleAlert;
  readonly Bug = Bug;
  readonly Share2 = Share2;
  readonly Bell = Bell;
  readonly ChevronLeft = ChevronLeft;
  readonly ChevronRight = ChevronRight;
  readonly Moon = Moon;
  readonly Sun = Sun;
  readonly User = User;
  readonly Search = Search;
  readonly Settings = Settings;
  readonly X = X;
  readonly Copyright = Copyright;

  private readonly router = inject(Router);
  private readonly auth = inject(AuthService);
  private readonly authStore = inject(AuthStore);
  private readonly eventsApi = inject(EventsApi);
  private readonly projectContext = inject(ProjectContextService);
  private readonly appVersionService = inject(AppVersionService);
  private readonly theme = inject(ThemeService);
  private readonly destroyRef = inject(DestroyRef);
  isSidebarExpanded = signal(true);
  isLoggingOut = signal(false);

  readonly searchQuery = signal('');
  readonly canSubmitSearch = computed(() => this.searchQuery().trim().length >= 2);

  readonly openEventsCount = signal<number | null>(null);
  readonly openEventsBadge = computed(() => {
    const count = this.openEventsCount();
    if (count === null) {
      return null;
    }
    if (count > 99) {
      return '99+';
    }
    return String(Math.max(0, count));
  });
  readonly availableProjects = computed(() => this.projectContext.projects());
  readonly selectedProjectId = computed(() => this.projectContext.selectedProjectId());
  readonly projectLoading = computed(() => this.projectContext.loading());
  readonly canManageProjects = computed(() => this.authStore.hasRole('ADMIN'));
  readonly canAccessSettings = computed(() => this.authStore.hasRole('ADMIN'));
  readonly appVersion = this.appVersionService.version;

  // Menu expansion signals
  isDataExpanded = signal(false);
  isSecurityExpanded = signal(false);
  isSettingsExpanded = signal(false);
  isDarkTheme = computed(() => this.theme.theme() === 'dark');
  themeToggleLabel = computed(() => (this.isDarkTheme() ? 'Light mode' : 'Dark mode'));

  toggleDataMenu(event?: Event) {
    event?.preventDefault();
    event?.stopPropagation();

    if (!this.isSidebarExpanded()) {
      this.isSidebarExpanded.set(true);
    }

    if (!this.isDataSectionActive()) {
      this.isDataExpanded.set(true);
      void this.router.navigate(['/data']);
      return;
    } else {
      this.isDataExpanded.update((v) => !v);
    }
  }

  toggleSecurityMenu(event?: Event) {
    event?.preventDefault();
    event?.stopPropagation();

    if (!this.isSidebarExpanded()) {
      this.isSidebarExpanded.set(true);
    }

    if (!this.isSecuritySectionActive()) {
      this.isSecurityExpanded.set(true);
      void this.router.navigate(['/security']);
      return;
    } else {
      this.isSecurityExpanded.update((v) => !v);
    }
  }

  toggleSettingsMenu(event?: Event) {
    event?.preventDefault();
    event?.stopPropagation();

    if (!this.isSidebarExpanded()) {
      this.isSidebarExpanded.set(true);
    }

    if (!this.isSettingsSectionActive()) {
      this.isSettingsExpanded.set(true);
      void this.router.navigate(['/admin/settings/general']);
      return;
    } else {
      this.isSettingsExpanded.update((v) => !v);
    }
  }

  toggleSidebar() {
    this.isSidebarExpanded.update((v) => !v);
  }

  toggleTheme() {
    this.theme.toggle();
  }

  openChangePassword(): void {
    const returnUrl = this.sanitizeReturnUrl(this.router.url);
    void this.router.navigate(['/account/change-password'], { queryParams: { returnUrl } });
  }

  async onLogout(): Promise<void> {
    if (this.isLoggingOut()) {
      return;
    }
    this.isLoggingOut.set(true);
    const redirect = this.sanitizeReturnUrl(this.router.url);
    try {
      await this.auth.performLogout();
    } finally {
      this.isLoggingOut.set(false);
    }
    void this.router.navigate(['/login'], { queryParams: { redirect } });
  }

  constructor() {
    // Keep the top search input in sync when user navigates via back/forward.
    this.syncSearchFromUrl(this.router.url);
    this.syncSidebarMenusFromUrl(this.router.url);
    void (async () => {
      await this.projectContext.initialize();
      await this.refreshOpenEventsCount();
    })();
    this.router.events
      .pipe(
        filter((event): event is NavigationEnd => event instanceof NavigationEnd),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe(() => {
        this.syncSearchFromUrl(this.router.url);
        this.syncSidebarMenusFromUrl(this.router.url);
        void this.refreshOpenEventsCount();
      });

    fromEvent(window, 'ctwall:events-updated')
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((event) => {
        const custom = event as CustomEvent<{ kind?: string }>;
        if (custom.detail?.kind === 'ack') {
          this.openEventsCount.update((count) => {
            if (count === null) {
              return 0;
            }
            return Math.max(0, count - 1);
          });
        }
        void this.refreshOpenEventsCount();
      });

    interval(30_000)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => void this.refreshOpenEventsCount());
  }

  onSearchInput(event: Event): void {
    const value = (event.target as HTMLInputElement | null)?.value ?? '';
    this.searchQuery.set(value);
  }

  submitSearch(): void {
    const q = this.searchQuery().trim();
    if (q.length < 2) {
      return;
    }
    void this.router.navigate(['/search/components'], {
      queryParams: { q, page: 1, pageSize: 50 },
    });
  }

  clearSearch(): void {
    this.searchQuery.set('');
    if (this.router.url.startsWith('/search/components')) {
      void this.router.navigate(['/search/components'], { queryParams: {} });
    }
  }

  openEvents(): void {
    void this.router.navigate(['/events']);
  }

  async onProjectSelected(projectId: string | null): Promise<void> {
    if (!projectId) {
      return;
    }
    const trimmed = projectId.trim();
    if (!trimmed) {
      return;
    }
    await this.projectContext.selectProject(trimmed);
    void this.refreshOpenEventsCount();
    // Force workspace refresh so singleton stores are reloaded under the new project scope.
    window.location.assign('/dashboard');
  }

  openManageProjects(): void {
    void this.router.navigate(['/admin/projects']);
  }

  private async refreshOpenEventsCount(): Promise<void> {
    try {
      const payload = await this.eventsApi.openCount();
      const count = typeof payload?.count === 'number' ? payload.count : 0;
      this.openEventsCount.set(count);
    } catch {
      // Keep UI quiet; failing to load badge count must not break navigation.
      this.openEventsCount.set(null);
    }
  }

  private syncSearchFromUrl(url: string): void {
    if (!url.startsWith('/search/components')) {
      return;
    }
    const tree = this.router.parseUrl(url);
    const q = typeof tree.queryParams['q'] === 'string' ? (tree.queryParams['q'] as string) : '';
    this.searchQuery.set(q);
  }

  private syncSidebarMenusFromUrl(url: string): void {
    this.isDataExpanded.set(this.isSectionUrl(url, '/data'));
    this.isSecurityExpanded.set(this.isSectionUrl(url, '/security'));
    this.isSettingsExpanded.set(this.isSectionUrl(url, '/admin/settings'));
  }

  isDataSectionActive(): boolean {
    return this.isSectionUrl(this.router.url, '/data');
  }

  isSecuritySectionActive(): boolean {
    return this.isSectionUrl(this.router.url, '/security');
  }

  isSettingsSectionActive(): boolean {
    return this.isSectionUrl(this.router.url, '/admin/settings');
  }

  private isSectionUrl(url: string, prefix: string): boolean {
    return (
      url === prefix ||
      url.startsWith(`${prefix}/`) ||
      url.startsWith(`${prefix}?`) ||
      url.startsWith(`${prefix};`) ||
      url.startsWith(`${prefix}#`)
    );
  }

  private sanitizeReturnUrl(value: string): string {
    if (!value) {
      return '/dashboard';
    }
    if (!value.startsWith('/') || value.startsWith('//')) {
      return '/dashboard';
    }
    if (value.startsWith('/login')) {
      return '/dashboard';
    }
    if (value.startsWith('/account/change-password')) {
      return '/dashboard';
    }
    return value;
  }
}
