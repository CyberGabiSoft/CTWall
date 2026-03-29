
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, DestroyRef, ErrorHandler, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { Filter, LucideAngularModule, Settings2 } from 'lucide-angular';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { interval } from 'rxjs';
import { DataTableComponent } from '../../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../../shared/ui/data-table/data-table.types';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
  AdvancedFilterPanelComponent
} from '../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { LoadingIndicatorComponent } from '../../../shared/ui/loading-indicator/loading-indicator.component';
import { EventsApi, EventsListQuery } from '../data-access/events.api';
import { EventAggregate, EventSeverity } from '../data-access/events.types';
import { EventDetailsDialogComponent } from './event-details-dialog.component';
import { AuthStore } from '../../auth/auth.store';

type LoadState = 'loading' | 'loaded' | 'error';
type StatusFilter = 'open' | 'acknowledged';
type SortDirection = 'asc' | 'desc';
type EventsColumnKey = 'severity' | 'category' | 'title' | 'occurrences' | 'lastSeenAt' | 'status';

const columns: ColumnDefinition[] = [
  { key: 'severity', label: 'Severity', sortKey: 'severity', filterKey: 'severity' },
  { key: 'category', label: 'Category', sortKey: 'category', filterKey: 'category' },
  { key: 'title', label: 'Title', sortKey: 'title', filterKey: 'title' },
  { key: 'occurrences', label: 'Occurrences', sortKey: 'occurrences', filterKey: 'occurrences' },
  { key: 'lastSeenAt', label: 'Last seen', sortKey: 'lastSeenAt', filterKey: 'lastSeenAt' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' }
];

const ALL_CATEGORIES: string[] = [
  'authn',
  'authz',
  'account',
  'token',
  'config',
  'data_import',
  'data_export',
  'malware',
  'source_sync',
  'api_error',
  'rate_limit',
  'infra_db',
  'infra_storage',
  'infra_external',
  'system'
];

@Component({
  selector: 'app-events-page',
  imports: [
    MatCardModule,
    MatButtonModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatSelectModule,
    MatDialogModule,
    LucideAngularModule,
    DataTableComponent,
    AdvancedFilterPanelComponent,
    LoadingIndicatorComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './events-page.component.html',
  styleUrl: './events-page.component.scss'
})
export class EventsPageComponent {
  protected readonly Filter = Filter;
  protected readonly Settings2 = Settings2;
  protected readonly columns = columns;
  protected readonly pageSizeOptions = [10, 25, 50, 100];
  protected readonly categories = ALL_CATEGORIES;
  protected readonly lockedColumns: EventsColumnKey[] = ['title'];

  private readonly api = inject(EventsApi);
  private readonly dialog = inject(MatDialog);
  private readonly errorHandler = inject(ErrorHandler);
  private readonly destroyRef = inject(DestroyRef);
  private readonly auth = inject(AuthStore);

  readonly isAdmin = computed(() => this.auth.hasRole('ADMIN'));

  readonly status = signal<LoadState>('loading');
  readonly errorMessage = signal<string | null>(null);
  readonly items = signal<EventAggregate[]>([]);
  readonly total = signal(0);

  readonly pageIndex = signal(0);
  readonly pageSize = signal(50);
  readonly totalPages = computed(() => {
    const size = this.pageSize();
    if (size <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(this.total() / size));
  });
  readonly columnOrder = signal<EventsColumnKey[]>(['severity', 'category', 'title', 'occurrences', 'lastSeenAt', 'status']);
  readonly tablePanelOpen = signal(false);
  readonly filterPanelOpen = signal(false);
  readonly filterVisible = signal<Record<EventsColumnKey, boolean>>({
    severity: false,
    category: false,
    title: false,
    occurrences: false,
    lastSeenAt: false,
    status: false
  });
  readonly columnFilters = signal<Record<EventsColumnKey, string>>({
    severity: '',
    category: '',
    title: '',
    occurrences: '',
    lastSeenAt: '',
    status: ''
  });
  readonly filterMode = signal<Record<EventsColumnKey, AdvancedFilterMode>>({
    severity: 'contains',
    category: 'contains',
    title: 'contains',
    occurrences: 'contains',
    lastSeenAt: 'contains',
    status: 'contains'
  });
  readonly multiFilters = signal<Record<EventsColumnKey, string[]>>({
    severity: [],
    category: [],
    title: [],
    occurrences: [],
    lastSeenAt: [],
    status: []
  });
  readonly filterOptions = computed<Record<EventsColumnKey, string[]>>(() => {
    const rows = this.items();
    return {
      severity: this.sortedOptions(rows.map((row) => this.rowValue(row, 'severity'))),
      category: this.sortedOptions(rows.map((row) => this.rowValue(row, 'category'))),
      title: this.sortedOptions(rows.map((row) => this.rowValue(row, 'title'))),
      occurrences: this.sortedOptions(rows.map((row) => this.rowValue(row, 'occurrences'))),
      lastSeenAt: this.sortedOptions(rows.map((row) => this.rowValue(row, 'lastSeenAt'))),
      status: this.sortedOptions(rows.map((row) => this.rowValue(row, 'status')))
    };
  });
  readonly advancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.filterMode();
    const filters = this.columnFilters();
    const multi = this.multiFilters();
    const options = this.filterOptions();
    return [
      {
        key: 'severity',
        label: 'Severity',
        mode: mode.severity,
        value: filters.severity,
        options: options.severity,
        selected: multi.severity
      },
      {
        key: 'category',
        label: 'Category',
        mode: mode.category,
        value: filters.category,
        options: options.category,
        selected: multi.category
      },
      {
        key: 'title',
        label: 'Title',
        mode: mode.title,
        value: filters.title,
        options: options.title,
        selected: multi.title
      },
      {
        key: 'occurrences',
        label: 'Occurrences',
        mode: mode.occurrences,
        value: filters.occurrences,
        options: options.occurrences,
        selected: multi.occurrences
      },
      {
        key: 'lastSeenAt',
        label: 'Last seen',
        mode: mode.lastSeenAt,
        value: filters.lastSeenAt,
        options: options.lastSeenAt,
        selected: multi.lastSeenAt
      },
      {
        key: 'status',
        label: 'Status',
        mode: mode.status,
        value: filters.status,
        options: options.status,
        selected: multi.status
      }
    ];
  });
  readonly filterRowVisible = computed(() => Object.values(this.filterVisible()).some(Boolean));
  readonly sortColumn = signal<EventsColumnKey | null>('lastSeenAt');
  readonly sortDir = signal<SortDirection>('desc');
  readonly availableColumns = computed(() => {
    const selected = new Set(this.columnOrder());
    return this.columns.filter((column) => !selected.has(column.key as EventsColumnKey));
  });
  readonly tableRows = computed(() => {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = this.items().filter((row) => {
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'severity'), modes.severity, filters.severity, selected.severity)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'category'), modes.category, filters.category, selected.category)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'title'), modes.title, filters.title, selected.title)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'occurrences'), modes.occurrences, filters.occurrences, selected.occurrences)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'lastSeenAt'), modes.lastSeenAt, filters.lastSeenAt, selected.lastSeenAt)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'status'), modes.status, filters.status, selected.status)) return false;
      return true;
    });
    const sortColumn = this.sortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.sortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) => {
      if (sortColumn === 'occurrences') {
        return ((left.occurrences ?? 0) - (right.occurrences ?? 0)) * mult;
      }
      if (sortColumn === 'lastSeenAt') {
        return (Date.parse(left.lastSeenAt ?? '') - Date.parse(right.lastSeenAt ?? '')) * mult;
      }
      return this.rowValue(left, sortColumn).localeCompare(this.rowValue(right, sortColumn), undefined, {
        sensitivity: 'base'
      }) * mult;
    });
  });

  readonly optionsOpen = signal(false);

  // Options (do not auto-fetch until Apply).
  readonly includeError = signal(true);
  readonly includeWarn = signal(false);
  readonly includeInfo = signal(false);
  readonly statusFilter = signal<StatusFilter>('open');
  readonly includeErrorCategories = signal<string[]>([]);
  readonly includeWarnCategories = signal<string[]>([]);
  readonly includeInfoCategories = signal<string[]>([]);
  readonly canApply = computed(() => {
    if (!this.includeError() && !this.includeWarn() && !this.includeInfo()) {
      return false;
    }
    // To avoid flood, require categories when enabling WARN/INFO.
    if (this.includeWarn() && this.includeWarnCategories().length === 0) {
      return false;
    }
    if (this.includeInfo() && this.includeInfoCategories().length === 0) {
      return false;
    }
    return true;
  });

  // Applied query snapshot (drives backend calls).
  private readonly appliedQuery = signal<EventsListQuery>({
    severities: ['ERROR'],
    status: 'open',
    categoriesError: [],
    categoriesWarn: [],
    categoriesInfo: [],
    page: 1,
    pageSize: 50
  });
  private loadRequestID = 0;

  // Export provider for DataTable (server paging + local filters).
  readonly exportAllEvents = async (): Promise<EventAggregate[]> => {
    const base = this.appliedQuery();
    const pageSize = 200;
    const maxRows = 10_000;

    const collected: EventAggregate[] = [];
    let page = 1;
    let totalPages = 1;

    while (page <= totalPages) {
      const payload = await this.api.list({
        severities: base.severities,
        status: base.status,
        categoriesError: base.categoriesError,
        categoriesWarn: base.categoriesWarn,
        categoriesInfo: base.categoriesInfo,
        q: base.q,
        page,
        pageSize
      });
      const items = payload.items ?? [];
      collected.push(...items);

      totalPages = typeof payload.totalPages === 'number' && payload.totalPages > 0 ? payload.totalPages : totalPages;
      if (collected.length >= maxRows) {
        break;
      }
      if (items.length < pageSize) {
        break;
      }
      page += 1;
    }

    // Apply the same client-side advanced filters + sort as the table.
    const filteredSorted = this.applyClientFiltersAndSort(collected);
    return filteredSorted.slice(0, maxRows);
  };

  constructor() {
    void this.loadEvents(true);

    // Background refresh while staying on the page (lightweight; no spinner flip).
    interval(30_000)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        if (this.status() !== 'loaded') {
          return;
        }
        void this.loadEvents(false, true);
      });
  }

  private applyClientFiltersAndSort(items: EventAggregate[]): EventAggregate[] {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = items.filter((row) => {
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'severity'), modes.severity, filters.severity, selected.severity)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'category'), modes.category, filters.category, selected.category)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'title'), modes.title, filters.title, selected.title)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'occurrences'), modes.occurrences, filters.occurrences, selected.occurrences)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'lastSeenAt'), modes.lastSeenAt, filters.lastSeenAt, selected.lastSeenAt)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'status'), modes.status, filters.status, selected.status)) return false;
      return true;
    });

    const sortColumn = this.sortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.sortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) => {
      if (sortColumn === 'occurrences') {
        return ((left.occurrences ?? 0) - (right.occurrences ?? 0)) * mult;
      }
      if (sortColumn === 'lastSeenAt') {
        return (Date.parse(left.lastSeenAt ?? '') - Date.parse(right.lastSeenAt ?? '')) * mult;
      }
      return (
        this.rowValue(left, sortColumn).localeCompare(this.rowValue(right, sortColumn), undefined, {
          sensitivity: 'base'
        }) * mult
      );
    });
  }

  toggleOptions(): void {
    this.optionsOpen.update((v) => !v);
  }

  toggleExtendedFilters(): void {
    this.filterPanelOpen.update((value) => !value);
  }

  setFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.filterMode.update((state) => ({ ...state, [key]: mode }));
    if (mode === 'contains') {
      this.multiFilters.update((state) => ({ ...state, [key]: [] }));
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: '' }));
  }

  setFilterValue(key: string, value: string): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setMultiFilter(key: string, values: string[]): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    this.multiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearFilters(): void {
    this.columnFilters.set({
      severity: '',
      category: '',
      title: '',
      occurrences: '',
      lastSeenAt: '',
      status: ''
    });
    this.filterMode.set({
      severity: 'contains',
      category: 'contains',
      title: 'contains',
      occurrences: 'contains',
      lastSeenAt: 'contains',
      status: 'contains'
    });
    this.multiFilters.set({
      severity: [],
      category: [],
      title: [],
      occurrences: [],
      lastSeenAt: [],
      status: []
    });
  }

  toggleTablePanel(): void {
    this.tablePanelOpen.update((value) => !value);
  }

  dropColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.columnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.columnOrder.set(next);
  }

  removeColumn(value: string): void {
    if (!this.isColumnKey(value) || this.lockedColumns.includes(value)) {
      return;
    }
    const next = this.columnOrder().filter((key) => key !== value);
    if (next.length < 1) {
      return;
    }
    this.columnOrder.set(next);
  }

  addColumn(value: string): void {
    if (!this.isColumnKey(value) || this.columnOrder().includes(value)) {
      return;
    }
    this.columnOrder.set([...this.columnOrder(), value]);
  }

  toggleFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!this.isColumnKey(key)) {
      return;
    }
    this.filterVisible.update((state) => {
      switch (key) {
        case 'severity':
          return { ...state, severity: !state.severity };
        case 'category':
          return { ...state, category: !state.category };
        case 'title':
          return { ...state, title: !state.title };
        case 'occurrences':
          return { ...state, occurrences: !state.occurrences };
        case 'lastSeenAt':
          return { ...state, lastSeenAt: !state.lastSeenAt };
        case 'status':
          return { ...state, status: !state.status };
      }
    });
  }

  setColumnFilter(key: string, event: Event): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.filterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.multiFilters.update((state) => ({ ...state, [key]: [] }));
    this.columnFilters.update((state) => {
      switch (key) {
        case 'severity':
          return { ...state, severity: value };
        case 'category':
          return { ...state, category: value };
        case 'title':
          return { ...state, title: value };
        case 'occurrences':
          return { ...state, occurrences: value };
        case 'lastSeenAt':
          return { ...state, lastSeenAt: value };
        case 'status':
          return { ...state, status: value };
      }
    });
  }

  toggleSort(key: string): void {
    if (!this.isColumnKey(key)) {
      return;
    }
    if (this.sortColumn() === key) {
      this.sortDir.set(this.sortDir() === 'asc' ? 'desc' : 'asc');
      return;
    }
    this.sortColumn.set(key);
    this.sortDir.set(key === 'occurrences' || key === 'lastSeenAt' ? 'desc' : 'asc');
  }

  applyOptions(): void {
    if (!this.canApply()) {
      return;
    }
    const severities = this.selectedSeverities();
    const categoriesError = this.includeError() ? this.includeErrorCategories() : [];
    const categoriesWarn = this.includeWarn() ? this.includeWarnCategories() : [];
    const categoriesInfo = this.includeInfo() ? this.includeInfoCategories() : [];

    this.pageIndex.set(0);
    this.pageSize.set(this.pageSize()); // keep current
    this.appliedQuery.set({
      severities,
      status: this.statusFilter(),
      categoriesError,
      categoriesWarn,
      categoriesInfo,
      page: 1,
      pageSize: this.pageSize()
    });
    void this.loadEvents(true);
  }

  async refresh(showSpinner = true): Promise<void> {
    await this.loadEvents(showSpinner, !showSpinner);
  }

  openDetails(row: EventAggregate): void {
    const key = (row?.eventKey ?? '').trim();
    if (!key) {
      return;
    }
    const ref = this.dialog.open(EventDetailsDialogComponent, {
      width: '980px',
      maxWidth: '96vw',
      data: { eventKey: key, canAck: this.isAdmin() }
    });
    ref.afterClosed().subscribe((result) => {
      if (result?.refresh) {
        void this.refresh(true);
      }
    });
  }

  rowValue(row: EventAggregate, columnKey: string): string {
    switch (columnKey) {
      case 'severity':
        return row.severity ?? 'ERROR';
      case 'category':
        return row.category ?? '-';
      case 'title':
        return row.title ?? '-';
      case 'occurrences':
        return String(typeof row.occurrences === 'number' ? row.occurrences : 0);
      case 'lastSeenAt':
        return row.lastSeenAt ?? '-';
      case 'status':
        return row.status ?? 'open';
      default:
        return '-';
    }
  }

  severityClass(value: EventSeverity | null | undefined): string {
    switch (value) {
      case 'ERROR':
        return 'sev sev--error';
      case 'WARN':
        return 'sev sev--warn';
      case 'INFO':
        return 'sev sev--info';
      default:
        return 'sev';
    }
  }

  statusClass(value: string | null | undefined): string {
    return value === 'acknowledged' ? 'status status--ack' : 'status status--open';
  }

  setPageSize(size: number): void {
    const pageSize = size > 0 ? size : 50;
    this.pageSize.set(pageSize);
    this.pageIndex.set(0);
    this.appliedQuery.set({ ...this.appliedQuery(), pageSize });
    void this.loadEvents(true);
  }

  prevPage(): void {
    const current = this.pageIndex() + 1;
    if (current <= 1) {
      return;
    }
    this.pageIndex.set(current - 2);
    void this.loadEvents(true);
  }

  nextPage(): void {
    const current = this.pageIndex() + 1;
    const totalPages = this.totalPages();
    if (current >= totalPages) {
      return;
    }
    this.pageIndex.set(current);
    void this.loadEvents(true);
  }

  private async loadEvents(showSpinner: boolean, silentError = false): Promise<void> {
    const requestID = ++this.loadRequestID;
    const q = this.appliedQuery();
    const page = this.pageIndex() + 1;
    const pageSize = this.pageSize();

    if (showSpinner || this.status() !== 'loaded') {
      this.status.set('loading');
    }
    this.errorMessage.set(null);

    try {
      const payload = await this.api.list({
        severities: q.severities,
        status: q.status,
        categoriesError: q.categoriesError,
        categoriesWarn: q.categoriesWarn,
        categoriesInfo: q.categoriesInfo,
        q: q.q,
        page,
        pageSize
      });
      if (requestID !== this.loadRequestID) {
        return;
      }
      this.items.set(payload.items ?? []);
      this.total.set(typeof payload.total === 'number' ? payload.total : 0);
      this.status.set('loaded');
    } catch (error) {
      if (requestID !== this.loadRequestID) {
        return;
      }
      if (silentError && !showSpinner) {
        return;
      }
      this.errorHandler.handleError(error);
      this.status.set('error');
      this.errorMessage.set('Failed to load events.');
    }
  }

  private selectedSeverities(): EventSeverity[] {
    const out: EventSeverity[] = [];
    if (this.includeError()) out.push('ERROR');
    if (this.includeWarn()) out.push('WARN');
    if (this.includeInfo()) out.push('INFO');
    return out;
  }

  private matchesFilter(value: string, needle: string): boolean {
    const query = needle.trim().toLowerCase();
    if (!query) {
      return true;
    }
    return value.toLowerCase().includes(query);
  }

  private matchesAdvancedFilter(
    value: string,
    mode: AdvancedFilterMode,
    containsValue: string,
    selectedValues: string[]
  ): boolean {
    if (mode === 'select') {
      if (selectedValues.length === 0) {
        return true;
      }
      return selectedValues.includes(value);
    }
    return this.matchesFilter(value, containsValue);
  }

  private sortedOptions(values: string[]): string[] {
    const unique = new Set<string>();
    values.forEach((value) => {
      const normalized = value.trim();
      if (normalized && normalized !== '-') {
        unique.add(normalized);
      }
    });
    return Array.from(unique).sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' }));
  }

  private isColumnKey(value: string): value is EventsColumnKey {
    return (
      value === 'severity' ||
      value === 'category' ||
      value === 'title' ||
      value === 'occurrences' ||
      value === 'lastSeenAt' ||
      value === 'status'
    );
  }

  // Categories are selected per severity in the UI and applied server-side.
}
