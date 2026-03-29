
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, signal } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { LucideAngularModule, ExternalLink, Filter } from 'lucide-angular';
import { DataTableComponent } from '../../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../../shared/ui/data-table/data-table.types';
import {
  DataTableExpandedDetailItem,
  DataTableExpandedDetailsComponent
} from '../../../shared/ui/data-table/data-table-expanded-details.component';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
  AdvancedFilterPanelComponent
} from '../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { SearchApi } from '../data-access/search.api';
import { ComponentOccurrence, MalwareVerdict } from '../data-access/search.types';
import { buildExtendedFilterQueryParams } from '../../../shared/utils/extended-filter-routing';
import { buildReturnToQueryParam } from '../../../shared/utils/return-navigation';
import { LoadState } from '../../../shared/types/load-state';


const columns: ColumnDefinition[] = [
  { key: 'purl', label: 'PURL', sortKey: 'purl', filterKey: 'purl', className: 'mono' },
  { key: 'malwareVerdict', label: 'Malware', sortKey: 'malwareVerdict', filterKey: 'malwareVerdict' },
  { key: 'productName', label: 'Product', sortKey: 'productName', filterKey: 'productName' },
  { key: 'scopeName', label: 'Scope', sortKey: 'scopeName', filterKey: 'scopeName' },
  { key: 'testName', label: 'Test', sortKey: 'testName', filterKey: 'testName' },
  { key: 'version', label: 'Version', sortKey: 'version', filterKey: 'version' },
  { key: 'pkgType', label: 'Type', sortKey: 'pkgType', filterKey: 'pkgType' }
];
type SortDirection = 'asc' | 'desc';
type SearchColumnKey = 'purl' | 'malwareVerdict' | 'productName' | 'scopeName' | 'testName' | 'version' | 'pkgType';

@Component({
  selector: 'app-component-occurrences-search',
  imports: [
    MatCardModule,
    MatButtonModule,
    LucideAngularModule,
    DataTableComponent,
    DataTableExpandedDetailsComponent,
    AdvancedFilterPanelComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './component-occurrences-search.component.html',
  styleUrl: './component-occurrences-search.component.scss'
})
export class ComponentOccurrencesSearchComponent {
  protected readonly Filter = Filter;
  protected readonly ExternalLink = ExternalLink;
  protected readonly columns = columns;
  protected readonly pageSizeOptions = [10, 25, 50, 100];
  protected readonly lockedColumns: SearchColumnKey[] = ['purl'];

  private readonly api = inject(SearchApi);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  private fetchSeq = 0;

  readonly q = signal('');
  readonly status = signal<LoadState>('idle');
  readonly errorMessage = signal<string | null>(null);

  readonly pageIndex = signal(0);
  readonly pageSize = signal(50);
  readonly total = signal(0);
  readonly rows = signal<ComponentOccurrence[]>([]);
  readonly columnOrder = signal<SearchColumnKey[]>(['purl', 'malwareVerdict', 'productName', 'scopeName', 'testName', 'version', 'pkgType']);
  readonly tablePanelOpen = signal(false);
  readonly expandedRows = signal<ReadonlySet<string>>(new Set());
  readonly filterPanelOpen = signal(false);
  readonly filterVisible = signal<Record<SearchColumnKey, boolean>>({
    purl: false,
    malwareVerdict: false,
    productName: false,
    scopeName: false,
    testName: false,
    version: false,
    pkgType: false
  });
  readonly columnFilters = signal<Record<SearchColumnKey, string>>({
    purl: '',
    malwareVerdict: '',
    productName: '',
    scopeName: '',
    testName: '',
    version: '',
    pkgType: ''
  });
  readonly filterMode = signal<Record<SearchColumnKey, AdvancedFilterMode>>({
    purl: 'contains',
    malwareVerdict: 'contains',
    productName: 'contains',
    scopeName: 'contains',
    testName: 'contains',
    version: 'contains',
    pkgType: 'contains'
  });
  readonly multiFilters = signal<Record<SearchColumnKey, string[]>>({
    purl: [],
    malwareVerdict: [],
    productName: [],
    scopeName: [],
    testName: [],
    version: [],
    pkgType: []
  });
  readonly filterOptions = computed<Record<SearchColumnKey, string[]>>(() => {
    const rows = this.rows();
    return {
      purl: this.sortedOptions(rows.map((row) => this.rowValue(row, 'purl'))),
      malwareVerdict: this.sortedOptions(rows.map((row) => this.rowValue(row, 'malwareVerdict'))),
      productName: this.sortedOptions(rows.map((row) => this.rowValue(row, 'productName'))),
      scopeName: this.sortedOptions(rows.map((row) => this.rowValue(row, 'scopeName'))),
      testName: this.sortedOptions(rows.map((row) => this.rowValue(row, 'testName'))),
      version: this.sortedOptions(rows.map((row) => this.rowValue(row, 'version'))),
      pkgType: this.sortedOptions(rows.map((row) => this.rowValue(row, 'pkgType')))
    };
  });
  readonly advancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.filterMode();
    const filters = this.columnFilters();
    const multi = this.multiFilters();
    const options = this.filterOptions();
    return [
      {
        key: 'purl',
        label: 'PURL',
        mode: mode.purl,
        value: filters.purl,
        options: options.purl,
        selected: multi.purl,
        containsPlaceholder: 'Contains PURL'
      },
      {
        key: 'malwareVerdict',
        label: 'Malware',
        mode: mode.malwareVerdict,
        value: filters.malwareVerdict,
        options: options.malwareVerdict,
        selected: multi.malwareVerdict
      },
      {
        key: 'productName',
        label: 'Product',
        mode: mode.productName,
        value: filters.productName,
        options: options.productName,
        selected: multi.productName
      },
      {
        key: 'scopeName',
        label: 'Scope',
        mode: mode.scopeName,
        value: filters.scopeName,
        options: options.scopeName,
        selected: multi.scopeName
      },
      {
        key: 'testName',
        label: 'Test',
        mode: mode.testName,
        value: filters.testName,
        options: options.testName,
        selected: multi.testName
      },
      {
        key: 'version',
        label: 'Version',
        mode: mode.version,
        value: filters.version,
        options: options.version,
        selected: multi.version
      },
      {
        key: 'pkgType',
        label: 'Type',
        mode: mode.pkgType,
        value: filters.pkgType,
        options: options.pkgType,
        selected: multi.pkgType
      }
    ];
  });
  readonly filterRowVisible = computed(() => Object.values(this.filterVisible()).some(Boolean));
  readonly sortColumn = signal<SearchColumnKey | null>('purl');
  readonly sortDir = signal<SortDirection>('asc');
  readonly availableColumns = computed(() => {
    const selected = new Set(this.columnOrder());
    return this.columns.filter((column) => !selected.has(column.key as SearchColumnKey));
  });
  readonly tableRows = computed(() => {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = this.rows().filter((row) => {
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'purl'), modes.purl, filters.purl, selected.purl)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'malwareVerdict'), modes.malwareVerdict, filters.malwareVerdict, selected.malwareVerdict)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'productName'), modes.productName, filters.productName, selected.productName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'scopeName'), modes.scopeName, filters.scopeName, selected.scopeName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'testName'), modes.testName, filters.testName, selected.testName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'version'), modes.version, filters.version, selected.version)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'pkgType'), modes.pkgType, filters.pkgType, selected.pkgType)) return false;
      return true;
    });
    const sortColumn = this.sortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.sortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort((left, right) =>
      this.rowValue(left, sortColumn).localeCompare(this.rowValue(right, sortColumn), undefined, { sensitivity: 'base' }) * mult
    );
  });

  readonly totalPages = computed(() => {
    const size = this.pageSize();
    if (size <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(this.total() / size));
  });

  // Export provider for DataTable (server paging + local filters).
  readonly exportAllOccurrences = async (): Promise<ComponentOccurrence[]> => {
    const q = this.q().trim();
    if (!q) {
      return [];
    }

    const pageSize = 200;
    const maxRows = 10_000;
    const payload0 = await this.api.searchComponentOccurrences(q, 1, pageSize);
    const total = typeof payload0.total === 'number' ? payload0.total : 0;
    const totalPages = pageSize > 0 ? Math.max(1, Math.ceil(total / pageSize)) : 1;

    const collected: ComponentOccurrence[] = [];
    collected.push(...(payload0.items ?? []));

    for (let page = 2; page <= totalPages; page += 1) {
      if (collected.length >= maxRows) {
        break;
      }
      const payload = await this.api.searchComponentOccurrences(q, page, pageSize);
      const items = payload.items ?? [];
      collected.push(...items);
      if (items.length < pageSize) {
        break;
      }
    }

    const filteredSorted = this.applyClientFiltersAndSort(collected);
    return filteredSorted.slice(0, maxRows);
  };

  constructor() {
    this.route.queryParamMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => {
        const q = (params.get('q') ?? '').trim();
        const page = Number(params.get('page') ?? '1');
        const pageSize = Number(params.get('pageSize') ?? '50');

        this.q.set(q);
        this.pageIndex.set(Number.isFinite(page) && page > 0 ? page - 1 : 0);
        this.pageSize.set(Number.isFinite(pageSize) && pageSize > 0 ? pageSize : 50);
        this.expandedRows.set(new Set());
      });

    effect(() => {
      const q = this.q();
      const pageIndex = this.pageIndex();
      const pageSize = this.pageSize();
      if (!q) {
        this.status.set('idle');
        this.errorMessage.set(null);
        this.rows.set([]);
        this.total.set(0);
        return;
      }

      const requestKey = `${q}::${pageIndex}::${pageSize}`;
      const seq = ++this.fetchSeq;
      this.status.set('loading');
      this.errorMessage.set(null);

      void (async () => {
        try {
          const payload = await this.api.searchComponentOccurrences(q, pageIndex + 1, pageSize);
          if (seq !== this.fetchSeq) return;
          // Guard against out-of-order responses.
          if (requestKey !== `${this.q()}::${this.pageIndex()}::${this.pageSize()}`) {
            return;
          }
          this.rows.set(payload.items ?? []);
          this.total.set(typeof payload.total === 'number' ? payload.total : 0);
          this.status.set('loaded');
          this.expandedRows.set(new Set());
        } catch {
          if (seq !== this.fetchSeq) return;
          this.status.set('error');
          this.errorMessage.set('Failed to load search results.');
        }
      })();
    });
  }

  verdictLabel(value: MalwareVerdict | null | undefined): string {
    if (!value) {
      return 'UNKNOWN';
    }
    return value;
  }

  verdictClass(value: MalwareVerdict | null | undefined): string {
    switch (value) {
      case 'MALWARE':
        return 'verdict verdict--malware';
      case 'CLEAN':
        return 'verdict verdict--clean';
      default:
        return 'verdict verdict--unknown';
    }
  }

  toggleExtendedFilters(): void {
    this.filterPanelOpen.update((value) => !value);
  }

  private applyClientFiltersAndSort(items: ComponentOccurrence[]): ComponentOccurrence[] {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = items.filter((row) => {
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'purl'), modes.purl, filters.purl, selected.purl)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'malwareVerdict'), modes.malwareVerdict, filters.malwareVerdict, selected.malwareVerdict)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'productName'), modes.productName, filters.productName, selected.productName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'scopeName'), modes.scopeName, filters.scopeName, selected.scopeName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'testName'), modes.testName, filters.testName, selected.testName)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'version'), modes.version, filters.version, selected.version)) return false;
      if (!this.matchesAdvancedFilter(this.rowValue(row, 'pkgType'), modes.pkgType, filters.pkgType, selected.pkgType)) return false;
      return true;
    });

    const sortColumn = this.sortColumn();
    if (!sortColumn) {
      return filtered;
    }
    const mult = this.sortDir() === 'asc' ? 1 : -1;
    return [...filtered].sort(
      (left, right) =>
        this.rowValue(left, sortColumn).localeCompare(this.rowValue(right, sortColumn), undefined, {
          sensitivity: 'base'
        }) * mult
    );
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
      purl: '',
      malwareVerdict: '',
      productName: '',
      scopeName: '',
      testName: '',
      version: '',
      pkgType: ''
    });
    this.filterMode.set({
      purl: 'contains',
      malwareVerdict: 'contains',
      productName: 'contains',
      scopeName: 'contains',
      testName: 'contains',
      version: 'contains',
      pkgType: 'contains'
    });
    this.multiFilters.set({
      purl: [],
      malwareVerdict: [],
      productName: [],
      scopeName: [],
      testName: [],
      version: [],
      pkgType: []
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
        case 'purl':
          return { ...state, purl: !state.purl };
        case 'malwareVerdict':
          return { ...state, malwareVerdict: !state.malwareVerdict };
        case 'productName':
          return { ...state, productName: !state.productName };
        case 'scopeName':
          return { ...state, scopeName: !state.scopeName };
        case 'testName':
          return { ...state, testName: !state.testName };
        case 'version':
          return { ...state, version: !state.version };
        case 'pkgType':
          return { ...state, pkgType: !state.pkgType };
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
        case 'purl':
          return { ...state, purl: value };
        case 'malwareVerdict':
          return { ...state, malwareVerdict: value };
        case 'productName':
          return { ...state, productName: value };
        case 'scopeName':
          return { ...state, scopeName: value };
        case 'testName':
          return { ...state, testName: value };
        case 'version':
          return { ...state, version: value };
        case 'pkgType':
          return { ...state, pkgType: value };
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
    this.sortDir.set('asc');
  }

  rowValue(row: ComponentOccurrence, columnKey: string): string {
    switch (columnKey) {
      case 'purl':
        return row.purl ?? '-';
      case 'malwareVerdict':
        return row.malwareVerdict ?? 'UNKNOWN';
      case 'productName':
        return row.productName ?? '-';
      case 'scopeName':
        return row.scopeName ?? '-';
      case 'testName':
        return row.testName ?? '-';
      case 'version':
        return row.version ?? '-';
      case 'pkgType':
        return row.pkgType ?? '-';
      default:
        return '-';
    }
  }

  occurrenceExpandedItems(row: ComponentOccurrence): DataTableExpandedDetailItem[] {
    const make = (
      key: string,
      label: string,
      value: string,
      options: { mono?: boolean; copyValue?: string } = {}
    ): DataTableExpandedDetailItem => ({
      key,
      label,
      value,
      copyValue: options.copyValue ?? value,
      mono: options.mono ?? false
    });

    return [
      make('componentId', 'Component ID', row.componentId || '-', { mono: true }),
      make('revisionId', 'Revision ID', row.revisionId || '-', { mono: true }),
      make('pkgName', 'Package name', row.pkgName || '-'),
      make('pkgNamespace', 'Package namespace', row.pkgNamespace || '-'),
      make('productId', 'Product ID', row.productId || '-', { mono: true }),
      make('scopeId', 'Scope ID', row.scopeId || '-', { mono: true }),
      make('testId', 'Test ID', row.testId || '-', { mono: true }),
      make('malwareFindingsCount', 'Malware findings count', String(row.malwareFindingsCount ?? 0)),
      make('malwareScannedAt', 'Malware scanned at', row.malwareScannedAt || '-', { mono: true }),
      make('malwareValidUntil', 'Malware valid until', row.malwareValidUntil || '-', { mono: true }),
      make('createdAt', 'Created at', row.createdAt || '-', { mono: true })
    ];
  }

  readonly occurrenceExpandedDetailsForTable = (row: unknown): ReadonlyArray<DataTableExpandedDetailItem> => {
    if (!this.isComponentOccurrence(row)) {
      return [];
    }
    return this.occurrenceExpandedItems(row);
  };

  readonly rowValueForExpandedDetails = (row: unknown, key: string): string => {
    if (!this.isComponentOccurrence(row)) {
      return '-';
    }
    return this.rowValue(row, key);
  };

  toggleRowExpanded(rowId: string | number): void {
    const key = String(rowId);
    if (!key) {
      return;
    }
    const next = new Set(this.expandedRows());
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    this.expandedRows.set(next);
  }

  openInExplorer(row: ComponentOccurrence): void {
    const testId = (row.testId ?? '').trim();
    const purl = (row.purl ?? '').trim();
    if (!testId) {
      return;
    }
    const prefillParams = buildExtendedFilterQueryParams('malware_detail_findings', {
      purl: { mode: 'contains', value: purl }
    });
    void this.router.navigate(['/security/explorer/tests', testId], {
      queryParams: {
        ...prefillParams,
        ...buildReturnToQueryParam(this.router.url),
        componentPurl: purl || null
      }
    });
  }

  setPageSize(size: number): void {
    const q = this.q();
    if (!q) {
      return;
    }
    const pageSize = size > 0 ? size : 50;
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { page: 1, pageSize },
      queryParamsHandling: 'merge',
      replaceUrl: true
    });
  }

  prevPage(): void {
    const q = this.q();
    if (!q) {
      return;
    }
    const current = this.pageIndex() + 1;
    if (current <= 1) {
      return;
    }
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { page: current - 1 },
      queryParamsHandling: 'merge',
      replaceUrl: true
    });
  }

  nextPage(): void {
    const q = this.q();
    if (!q) {
      return;
    }
    const current = this.pageIndex() + 1;
    const totalPages = this.totalPages();
    if (current >= totalPages) {
      return;
    }
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { page: current + 1 },
      queryParamsHandling: 'merge',
      replaceUrl: true
    });
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

  private isColumnKey(value: string): value is SearchColumnKey {
    return (
      value === 'purl' ||
      value === 'malwareVerdict' ||
      value === 'productName' ||
      value === 'scopeName' ||
      value === 'testName' ||
      value === 'version' ||
      value === 'pkgType'
    );
  }

  private isComponentOccurrence(value: unknown): value is ComponentOccurrence {
    return typeof value === 'object' && value !== null && 'componentId' in value;
  }
}
