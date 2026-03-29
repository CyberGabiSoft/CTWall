
import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  OnInit,
  WritableSignal,
  computed,
  effect,
  inject,
  signal
} from '@angular/core';
import { DragDropModule, CdkDragDrop } from '@angular/cdk/drag-drop';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatOptionModule } from '@angular/material/core';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatDialog, MatDialogModule } from '@angular/material/dialog';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import {
  DataTableExpandedDetailItem,
  DataTableExpandedDetailsComponent
} from '../../../../shared/ui/data-table/data-table-expanded-details.component';
import {
  AdvancedFilterPanelComponent
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { CopyBlockComponent } from '../../../../shared/ui/copy-block/copy-block.component';
import { SecurityStore } from '../../state/security.store';
import { AuthStore } from '../../../auth/auth.store';
import {
  buildOsvConfigDraft,
  buildOsvUpdatePayload,
  OsvConfigDraft
} from '../../data-access/security.utils';
import { MalwareSource, ScanComponentResult } from '../../data-access/security.types';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { Filter, LucideAngularModule } from 'lucide-angular';
import type { LoadState } from '../../state/security.store';
import { SyncErrorsDialogComponent, type SyncErrorsDialogData } from '../sync-errors-dialog/sync-errors-dialog.component';
import { mapDeleteValue, mapSetValue } from '../../../../shared/utils/map-utils';
import {
  buildFilterModes,
  buildFilterValues,
  buildFilterVisibility,
  buildMultiFilters,
  type FilterMode
} from '../../../../shared/utils/table-filter-records';
import {
  findingsAdvancedKeys,
  findingsColumnDefinitions,
  pageSizes,
  recomputeHistoryAdvancedKeys,
  recomputeHistoryColumnDefinitions,
  syncHistoryAdvancedKeys,
  syncHistoryAutoRefreshIntervalMs,
  syncHistoryAutoRefreshStaleMs,
  syncHistoryColumnDefinitions
} from './security-sources.tables';
import {
  applyColumnFilters,
  applyGlobalFilter,
  applySelectFilters,
  applySort,
  buildFilterOptions,
  resetFiltersForSelectModes,
  SortDirection,
  toExpandedDetails
} from './security-sources.utils';
import {
  addTableColumn,
  applyFilterMode,
  applyFilterValue,
  applyMultiFilter,
  clearTableFilters,
  dropTableColumn,
  nextTablePage,
  prevTablePage,
  removeTableColumn,
  setTableColumnFilter,
  setTableColumnQuery,
  setTablePageSize,
  TableStateBindings,
  togglePanel,
  toggleTableFilterVisibility,
  toggleTableSortState,
} from './security-sources.table-actions';
import {
  buildFindingsAdvancedFields,
  buildRecomputeHistoryAdvancedFields,
  buildRecomputeHistoryDetailMap,
  buildRecomputeHistoryRows,
  buildSyncHistoryAdvancedFields,
  buildSyncHistoryDetailMap,
  buildSyncHistoryRows,
  findingDisplayValue,
  findingValue,
  findingsDetailRows,
  findingsDetailsJson,
  findingsEvidence,
  isScanComponentResult,
  isSyncHistoryRow,
  recomputeHistoryActionLabel,
  recomputeHistoryStatusClass,
  recomputeHistoryValue,
  RecomputeHistoryDetailEntry,
  RecomputeHistoryRow,
  sourceConfigValue,
  syncHistoryActionLabel,
  syncHistoryStatusClass,
  syncHistoryValue,
  SyncHistoryDetailEntry,
  SyncHistoryRow,
} from './security-sources.mapper';
type RecomputeHistoryMode = 'source' | 'summaries';
type SourcesTableKind = 'findings' | 'syncHistory' | 'recomputeHistory';

type SourcesTableBindings = TableStateBindings & {
  tablePanelOpen: WritableSignal<boolean>;
  filterPanelOpen: WritableSignal<boolean>;
  totalPages: () => number;
  columns: readonly ColumnDefinition[];
  advancedKeys: readonly string[];
};

@Component({
  selector: 'app-security-sources',
  imports: [
    DragDropModule,
    MatAutocompleteModule,
    MatButtonModule,
    MatButtonToggleModule,
    MatCardModule,
    MatChipsModule,
    MatOptionModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    MatDialogModule,
    MatSnackBarModule,
    DataTableComponent,
    DataTableExpandedDetailsComponent,
    CopyBlockComponent,
    AdvancedFilterPanelComponent,
    LoadingIndicatorComponent,
    LucideAngularModule
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './security-sources.component.html',
  styleUrl: './security-sources.component.scss'
})
export class SecuritySourcesComponent implements OnInit {
  private readonly store = inject(SecurityStore);
  private readonly auth = inject(AuthStore);
  private readonly snackBar = inject(MatSnackBar);
  private readonly dialog = inject(MatDialog);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly Filter = Filter;
  readonly canAdmin = computed(() => this.auth.hasRole('ADMIN'));
  readonly summaryRecomputeLoadState = this.store.summaryRecomputeLoadState;

  readonly sources = this.store.sources;
  readonly sourcesLoadState = this.store.sourcesLoadState;
  readonly lastSync = this.store.lastSync;

  readonly selectedSourceId = signal<string | null>(null);
  readonly configDrafts = signal<Map<string, OsvConfigDraft>>(new Map());

  readonly findingsColumnOrder = signal(findingsColumnDefinitions.map((column) => column.key));
  readonly findingsColumnQuery = signal('');
  readonly findingsTablePanelOpen = signal(false);
  readonly findingsFilterPanelOpen = signal(false);
  readonly findingsFilterVisible = signal<Record<string, boolean>>(buildFilterVisibility(findingsColumnDefinitions));
  readonly findingsColumnFilters = signal<Record<string, string>>(buildFilterValues(findingsColumnDefinitions));
  readonly findingsFilterMode = signal<Record<string, FilterMode>>(buildFilterModes(findingsAdvancedKeys));
  readonly findingsMultiFilters = signal<Record<string, string[]>>(buildMultiFilters(findingsAdvancedKeys));
  readonly findingsSortColumn = signal<string | null>(null);
  readonly findingsSortDir = signal<SortDirection>('asc');

  readonly recomputeHistoryMode = signal<RecomputeHistoryMode>('source');

  readonly recomputeHistoryFilter = signal('');
  readonly recomputeHistoryColumnOrder = signal(recomputeHistoryColumnDefinitions.map((column) => column.key));
  readonly recomputeHistoryColumnQuery = signal('');
  readonly recomputeHistoryTablePanelOpen = signal(false);
  readonly recomputeHistoryFilterPanelOpen = signal(false);
  readonly recomputeHistoryFilterVisible = signal<Record<string, boolean>>(
    buildFilterVisibility(recomputeHistoryColumnDefinitions)
  );
  readonly recomputeHistoryColumnFilters = signal<Record<string, string>>(
    buildFilterValues(recomputeHistoryColumnDefinitions)
  );
  readonly recomputeHistoryFilterMode = signal<Record<string, FilterMode>>(buildFilterModes(recomputeHistoryAdvancedKeys));
  readonly recomputeHistoryMultiFilters = signal<Record<string, string[]>>(buildMultiFilters(recomputeHistoryAdvancedKeys));
  readonly recomputeHistorySortColumn = signal<string | null>(null);
  readonly recomputeHistorySortDir = signal<SortDirection>('asc');

  readonly syncHistoryFilter = signal('');
  readonly syncHistoryColumnOrder = signal(syncHistoryColumnDefinitions.map((column) => column.key));
  readonly syncHistoryColumnQuery = signal('');
  readonly syncHistoryTablePanelOpen = signal(false);
  readonly syncHistoryFilterPanelOpen = signal(false);
  readonly syncHistoryFilterVisible = signal<Record<string, boolean>>(
    buildFilterVisibility(syncHistoryColumnDefinitions)
  );
  readonly syncHistoryColumnFilters = signal<Record<string, string>>(
    buildFilterValues(syncHistoryColumnDefinitions)
  );
  readonly syncHistoryFilterMode = signal<Record<string, FilterMode>>(buildFilterModes(syncHistoryAdvancedKeys));
  readonly syncHistoryMultiFilters = signal<Record<string, string[]>>(buildMultiFilters(syncHistoryAdvancedKeys));
  readonly syncHistorySortColumn = signal<string | null>(null);
  readonly syncHistorySortDir = signal<SortDirection>('asc');

  readonly findingsPageSizeOptions = pageSizes;
  readonly findingsPageSize = signal(25);
  readonly findingsPageIndex = signal(0);

  readonly recomputeHistoryPageSizeOptions = pageSizes;
  readonly recomputeHistoryPageSize = signal(25);
  readonly recomputeHistoryPageIndex = signal(0);

  readonly syncHistoryPageSizeOptions = pageSizes;
  readonly syncHistoryPageSize = signal(25);
  readonly syncHistoryPageIndex = signal(0);

  readonly selectedSource = computed(() => {
    const id = this.selectedSourceId();
    if (!id) {
      return undefined;
    }
    return this.sources().find((source) => source.id === id);
  });

  readonly findingsStatus = computed(() => {
    const id = this.selectedSourceId();
    if (!id) {
      return 'idle';
    }
    return this.store.getFindingsStatus(id);
  });
  readonly findingsTableStatus = computed(() => {
    const status = this.findingsStatus();
    return status === 'idle' ? 'loaded' : status;
  });

  readonly findings = computed(() => {
    const id = this.selectedSourceId();
    if (!id) {
      return [];
    }
    return this.store.getFindings(id);
  });

  readonly filteredFindings = computed(() => {
    const columnFilters = this.findingsColumnFilters();
    const filterModes = this.findingsFilterMode();
    const items = this.findings();
    const selectFiltered = applySelectFilters(
      items,
      filterModes,
      this.findingsMultiFilters(),
      (item, key) => this.findingValue(item, key)
    );
    const normalizedFilters = resetFiltersForSelectModes(columnFilters, filterModes);
    return applyColumnFilters(selectFiltered, normalizedFilters, (item, key) => this.findingValue(item, key));
  });

  readonly sortedFindings = computed(() => {
    const items = this.filteredFindings();
    const sortColumn = this.findingsSortColumn();
    if (!sortColumn) {
      return items;
    }
    return applySort(items, sortColumn, this.findingsSortDir(), (item, key) =>
      this.findingValue(item, key)
    );
  });

  readonly pagedFindings = computed(() => {
    const size = this.findingsPageSize();
    const index = this.findingsPageIndex();
    const items = this.sortedFindings();
    if (size === 0) {
      return items;
    }
    const start = index * size;
    return items.slice(start, start + size);
  });

  readonly findingsTotalPages = computed(() => {
    const size = this.findingsPageSize();
    const total = this.sortedFindings().length;
    if (size === 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(total / size));
  });

  readonly findingsVisibleColumns = computed(() => {
    const order = this.findingsColumnOrder();
    const byKey = new Map(findingsColumnDefinitions.map((column) => [column.key, column]));
    return order.map((key) => byKey.get(key)).filter((column): column is ColumnDefinition => !!column);
  });

  readonly findingsAvailableColumns = computed(() => {
    const query = this.findingsColumnQuery().trim().toLowerCase();
    const current = new Set(this.findingsColumnOrder());
    return findingsColumnDefinitions.filter((column) => {
      if (current.has(column.key)) {
        return false;
      }
      if (!query) {
        return true;
      }
      return column.label.toLowerCase().includes(query);
    });
  });

  readonly findingsFilterRowVisible = computed(() =>
    Object.values(this.findingsFilterVisible()).some(Boolean)
  );

  readonly findingsFilterOptions = computed(() =>
    buildFilterOptions(this.findings(), findingsAdvancedKeys, (item, key) => this.findingValue(item, key))
  );

  readonly findingsAdvancedFields = computed(() =>
    buildFindingsAdvancedFields(
      this.findingsFilterMode(),
      this.findingsColumnFilters(),
      this.findingsMultiFilters(),
      this.findingsFilterOptions()
    )
  );
  readonly findingsExpanded = signal<Set<string>>(new Set());

  readonly syncHistoryStatus = computed(() => {
    const id = this.selectedSourceId();
    if (!id) {
      return 'idle';
    }
    return this.store.getSyncHistoryStatus(id);
  });
  readonly syncHistoryTableStatus = computed(() => {
    const status = this.syncHistoryStatus();
    return status === 'idle' ? 'loaded' : status;
  });

  readonly syncHistory = computed(() => {
    const id = this.selectedSourceId();
    if (!id) {
      return [];
    }
    return this.store.getSyncHistory(id);
  });

  syncHistoryExpandedItems(entry: SyncHistoryDetailEntry): DataTableExpandedDetailItem[] {
    return toExpandedDetails(entry.details);
  }

  syncHistoryHasErrors(row: unknown): boolean {
    if (!isSyncHistoryRow(row)) {
      return false;
    }
    return row.errorsCount > 0;
  }

  openSyncErrors(row: unknown, event?: Event): void {
    event?.stopPropagation();
    if (!isSyncHistoryRow(row)) {
      return;
    }
    const sourceId = this.selectedSourceId();
    if (!sourceId) {
      return;
    }
    const data: SyncErrorsDialogData = { sourceId, syncId: row.syncId };
    this.dialog.open<SyncErrorsDialogComponent, SyncErrorsDialogData>(SyncErrorsDialogComponent, {
      data,
      width: 'min(1100px, 96vw)',
      maxWidth: '96vw'
    });
  }

  findingsExpandedItems(row: unknown): DataTableExpandedDetailItem[] {
    if (!isScanComponentResult(row)) {
      return [];
    }
    return toExpandedDetails(findingsDetailRows(row));
  }

  readonly recomputeHistoryStatus = computed(() => {
    const mode = this.recomputeHistoryMode();
    if (mode === 'summaries') {
      return this.store.getSummaryRecomputeHistoryStatus();
    }
    const id = this.selectedSourceId();
    if (!id) {
      return 'idle';
    }
    return this.store.getSourceResultsRecomputeHistoryStatus(id);
  });
  readonly recomputeHistoryTableStatus = computed(() => {
    const status = this.recomputeHistoryStatus();
    return status === 'idle' ? 'loaded' : status;
  });

  readonly recomputeHistory = computed(() => {
    const mode = this.recomputeHistoryMode();
    if (mode === 'summaries') {
      return this.store.getSummaryRecomputeHistory();
    }
    const id = this.selectedSourceId();
    if (!id) {
      return [];
    }
    return this.store.getSourceResultsRecomputeHistory(id);
  });

  recomputeHistoryExpandedItems(entry: RecomputeHistoryDetailEntry): DataTableExpandedDetailItem[] {
    return toExpandedDetails(entry.details);
  }

  readonly recomputeHistoryRows = computed(() => buildRecomputeHistoryRows(this.recomputeHistory()));
  readonly recomputeHistoryEntryDetailsById = computed(() =>
    buildRecomputeHistoryDetailMap(this.recomputeHistory())
  );

  readonly filteredRecomputeHistory = computed(() => {
    const filter = this.recomputeHistoryFilter().trim().toLowerCase();
    const columnFilters = this.recomputeHistoryColumnFilters();
    const filterModes = this.recomputeHistoryFilterMode();
    const items = this.recomputeHistoryRows();
    const filtered = applyGlobalFilter(items, filter, recomputeHistoryColumnDefinitions, (item, key) =>
      this.recomputeHistoryValue(item, key)
    );
    const selectFiltered = applySelectFilters(
      filtered,
      filterModes,
      this.recomputeHistoryMultiFilters(),
      (item, key) => this.recomputeHistoryValue(item, key)
    );
    const normalizedFilters = resetFiltersForSelectModes(columnFilters, filterModes);
    return applyColumnFilters(selectFiltered, normalizedFilters, (item, key) => this.recomputeHistoryValue(item, key));
  });

  readonly sortedRecomputeHistory = computed(() => {
    const items = this.filteredRecomputeHistory();
    const sortColumn = this.recomputeHistorySortColumn();
    if (!sortColumn) {
      return items;
    }
    return applySort(items, sortColumn, this.recomputeHistorySortDir(), (item, key) =>
      this.recomputeHistoryValue(item, key)
    );
  });

  readonly pagedRecomputeHistory = computed(() => {
    const size = this.recomputeHistoryPageSize();
    const index = this.recomputeHistoryPageIndex();
    const items = this.sortedRecomputeHistory();
    if (size === 0) {
      return items;
    }
    const start = index * size;
    return items.slice(start, start + size);
  });

  readonly recomputeHistoryTotalPages = computed(() => {
    const size = this.recomputeHistoryPageSize();
    const total = this.sortedRecomputeHistory().length;
    if (size === 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(total / size));
  });

  readonly recomputeHistoryVisibleColumns = computed(() => {
    const order = this.recomputeHistoryColumnOrder();
    const byKey = new Map(recomputeHistoryColumnDefinitions.map((column) => [column.key, column]));
    return order.map((key) => byKey.get(key)).filter((column): column is ColumnDefinition => !!column);
  });

  readonly recomputeHistoryAvailableColumns = computed(() => {
    const query = this.recomputeHistoryColumnQuery().trim().toLowerCase();
    const current = new Set(this.recomputeHistoryColumnOrder());
    return recomputeHistoryColumnDefinitions.filter((column) => {
      if (current.has(column.key)) {
        return false;
      }
      if (!query) {
        return true;
      }
      return column.label.toLowerCase().includes(query);
    });
  });

  readonly recomputeHistoryFilterRowVisible = computed(() =>
    Object.values(this.recomputeHistoryFilterVisible()).some(Boolean)
  );

  readonly recomputeHistoryFilterOptions = computed(() =>
    buildFilterOptions(
      this.recomputeHistoryRows(),
      recomputeHistoryAdvancedKeys,
      (item, key) => this.recomputeHistoryValue(item, key)
    )
  );

  readonly recomputeHistoryAdvancedFields = computed(() =>
    buildRecomputeHistoryAdvancedFields(
      this.recomputeHistoryFilterMode(),
      this.recomputeHistoryColumnFilters(),
      this.recomputeHistoryMultiFilters(),
      this.recomputeHistoryFilterOptions()
    )
  );
  readonly recomputeHistoryExpanded = signal<Set<string>>(new Set());

  readonly syncHistoryRows = computed(() => buildSyncHistoryRows(this.syncHistory()));
  readonly syncHistoryEntryDetailsById = computed(() => buildSyncHistoryDetailMap(this.syncHistory()));

  readonly filteredSyncHistory = computed(() => {
    const filter = this.syncHistoryFilter().trim().toLowerCase();
    const columnFilters = this.syncHistoryColumnFilters();
    const filterModes = this.syncHistoryFilterMode();
    const items = this.syncHistoryRows();
    const filtered = applyGlobalFilter(items, filter, syncHistoryColumnDefinitions, (item, key) =>
      this.syncHistoryValue(item, key)
    );
    const selectFiltered = applySelectFilters(
      filtered,
      filterModes,
      this.syncHistoryMultiFilters(),
      (item, key) => this.syncHistoryValue(item, key)
    );
    const normalizedFilters = resetFiltersForSelectModes(columnFilters, filterModes);
    return applyColumnFilters(selectFiltered, normalizedFilters, (item, key) => this.syncHistoryValue(item, key));
  });

  readonly sortedSyncHistory = computed(() => {
    const items = this.filteredSyncHistory();
    const sortColumn = this.syncHistorySortColumn();
    if (!sortColumn) {
      return items;
    }
    return applySort(items, sortColumn, this.syncHistorySortDir(), (item, key) =>
      this.syncHistoryValue(item, key)
    );
  });

  readonly pagedSyncHistory = computed(() => {
    const size = this.syncHistoryPageSize();
    const index = this.syncHistoryPageIndex();
    const items = this.sortedSyncHistory();
    if (size === 0) {
      return items;
    }
    const start = index * size;
    return items.slice(start, start + size);
  });

  readonly syncHistoryTotalPages = computed(() => {
    const size = this.syncHistoryPageSize();
    const total = this.sortedSyncHistory().length;
    if (size === 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(total / size));
  });

  readonly syncHistoryVisibleColumns = computed(() => {
    const order = this.syncHistoryColumnOrder();
    const byKey = new Map(syncHistoryColumnDefinitions.map((column) => [column.key, column]));
    return order.map((key) => byKey.get(key)).filter((column): column is ColumnDefinition => !!column);
  });

  readonly syncHistoryAvailableColumns = computed(() => {
    const query = this.syncHistoryColumnQuery().trim().toLowerCase();
    const current = new Set(this.syncHistoryColumnOrder());
    return syncHistoryColumnDefinitions.filter((column) => {
      if (current.has(column.key)) {
        return false;
      }
      if (!query) {
        return true;
      }
      return column.label.toLowerCase().includes(query);
    });
  });

  readonly syncHistoryFilterRowVisible = computed(() =>
    Object.values(this.syncHistoryFilterVisible()).some(Boolean)
  );

  readonly syncHistoryFilterOptions = computed(() =>
    buildFilterOptions(
      this.syncHistoryRows(),
      syncHistoryAdvancedKeys,
      (item, key) => this.syncHistoryValue(item, key)
    )
  );

  readonly syncHistoryAdvancedFields = computed(() =>
    buildSyncHistoryAdvancedFields(
      this.syncHistoryFilterMode(),
      this.syncHistoryColumnFilters(),
      this.syncHistoryMultiFilters(),
      this.syncHistoryFilterOptions()
    )
  );
  readonly syncHistoryExpanded = signal<Set<string>>(new Set());
  readonly syncHistoryAutoRefreshInFlight = signal(false);
  readonly syncHistoryKickRefresh = signal(false);
  private syncHistoryKickRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  readonly syncHistoryActionLabel = syncHistoryActionLabel;
  readonly recomputeHistoryActionLabel = recomputeHistoryActionLabel;
  readonly recomputeHistoryStatusClass = recomputeHistoryStatusClass;
  readonly syncHistoryStatusClass = syncHistoryStatusClass;
  readonly findingsEvidence = findingsEvidence;
  readonly findingsDetailsJson = findingsDetailsJson;
  readonly findingValue = findingValue;
  readonly recomputeHistoryValue = recomputeHistoryValue;
  readonly syncHistoryValue = syncHistoryValue;

  readonly syncHistoryHasActiveRun = computed(() => {
    const rows = this.syncHistoryRows();
    const active = rows.find((row) => row.statusKind === 'started');
    if (!active) {
      return false;
    }
    const loggedAtMs = Date.parse(active.loggedAt);
    if (Number.isNaN(loggedAtMs)) {
      return true;
    }
    return Date.now() - loggedAtMs < syncHistoryAutoRefreshStaleMs;
  });

  private readonly tableBindings: Record<SourcesTableKind, SourcesTableBindings> = {
    findings: {
      tablePanelOpen: this.findingsTablePanelOpen,
      filterPanelOpen: this.findingsFilterPanelOpen,
      columnOrder: this.findingsColumnOrder,
      columnQuery: this.findingsColumnQuery,
      filterVisible: this.findingsFilterVisible,
      columnFilters: this.findingsColumnFilters,
      filterMode: this.findingsFilterMode,
      multiFilters: this.findingsMultiFilters,
      sortColumn: this.findingsSortColumn,
      sortDir: this.findingsSortDir,
      pageSize: this.findingsPageSize,
      pageIndex: this.findingsPageIndex,
      totalPages: this.findingsTotalPages,
      columns: findingsColumnDefinitions,
      advancedKeys: findingsAdvancedKeys
    },
    syncHistory: {
      tablePanelOpen: this.syncHistoryTablePanelOpen,
      filterPanelOpen: this.syncHistoryFilterPanelOpen,
      columnOrder: this.syncHistoryColumnOrder,
      columnQuery: this.syncHistoryColumnQuery,
      filterVisible: this.syncHistoryFilterVisible,
      columnFilters: this.syncHistoryColumnFilters,
      filterMode: this.syncHistoryFilterMode,
      multiFilters: this.syncHistoryMultiFilters,
      sortColumn: this.syncHistorySortColumn,
      sortDir: this.syncHistorySortDir,
      pageSize: this.syncHistoryPageSize,
      pageIndex: this.syncHistoryPageIndex,
      totalPages: this.syncHistoryTotalPages,
      columns: syncHistoryColumnDefinitions,
      advancedKeys: syncHistoryAdvancedKeys
    },
    recomputeHistory: {
      tablePanelOpen: this.recomputeHistoryTablePanelOpen,
      filterPanelOpen: this.recomputeHistoryFilterPanelOpen,
      columnOrder: this.recomputeHistoryColumnOrder,
      columnQuery: this.recomputeHistoryColumnQuery,
      filterVisible: this.recomputeHistoryFilterVisible,
      columnFilters: this.recomputeHistoryColumnFilters,
      filterMode: this.recomputeHistoryFilterMode,
      multiFilters: this.recomputeHistoryMultiFilters,
      sortColumn: this.recomputeHistorySortColumn,
      sortDir: this.recomputeHistorySortDir,
      pageSize: this.recomputeHistoryPageSize,
      pageIndex: this.recomputeHistoryPageIndex,
      totalPages: this.recomputeHistoryTotalPages,
      columns: recomputeHistoryColumnDefinitions,
      advancedKeys: recomputeHistoryAdvancedKeys
    }
  };

  constructor() {
    effect(() => {
      const sources = this.sources();
      const selectedSourceId = this.selectedSourceId();
      if (selectedSourceId && sources.some((source) => source.id === selectedSourceId)) {
        return;
      }
      if (sources.length > 0) {
        this.selectedSourceId.set(sources[0].id);
        return;
      }
      if (selectedSourceId) {
        this.selectedSourceId.set(null);
      }
    });

    effect(() => {
      this.findingsColumnFilters();
      this.findingsMultiFilters();
      this.selectedSourceId();
      this.findingsPageIndex.set(0);
      this.findingsExpanded.set(new Set());
    });

    effect(() => {
      this.recomputeHistoryFilter();
      this.recomputeHistoryColumnFilters();
      this.recomputeHistoryMultiFilters();
      this.selectedSourceId();
      this.recomputeHistoryMode();
      this.recomputeHistoryPageIndex.set(0);
      this.recomputeHistoryExpanded.set(new Set());
    });

    effect(() => {
      this.syncHistoryFilter();
      this.syncHistoryColumnFilters();
      this.syncHistoryMultiFilters();
      this.selectedSourceId();
      this.syncHistoryPageIndex.set(0);
      this.syncHistoryExpanded.set(new Set());
    });

    effect(() => {
      const sourceId = this.selectedSourceId();
      if (sourceId) {
        void this.store.ensureSyncHistory(sourceId);
      }
    });

    effect((onCleanup) => {
      const sourceId = this.selectedSourceId();
      const loadState = this.syncHistoryStatus();
      const shouldPoll = this.syncHistoryHasActiveRun() || this.syncHistoryKickRefresh();
      if (!sourceId || loadState !== 'loaded' || !shouldPoll) {
        return;
      }

      const intervalId = window.setInterval(() => {
        if (this.syncHistoryAutoRefreshInFlight()) {
          return;
        }
        this.syncHistoryAutoRefreshInFlight.set(true);
        this.store
          .refreshSyncHistorySilent(sourceId)
          .catch(() => undefined)
          .finally(() => this.syncHistoryAutoRefreshInFlight.set(false));
      }, syncHistoryAutoRefreshIntervalMs);

      onCleanup(() => window.clearInterval(intervalId));
    });

    effect(() => {
      const mode = this.recomputeHistoryMode();
      if (mode === 'summaries') {
        void this.store.ensureSummaryRecomputeHistory();
        return;
      }
      const sourceId = this.selectedSourceId();
      if (sourceId) {
        void this.store.ensureSourceResultsRecomputeHistory(sourceId);
      }
    });

    this.destroyRef.onDestroy(() => {
      if (this.syncHistoryKickRefreshTimer !== null) {
        window.clearTimeout(this.syncHistoryKickRefreshTimer);
        this.syncHistoryKickRefreshTimer = null;
      }
    });
  }

  ngOnInit(): void {
    this.store.ensureSources();
  }

  selectSource(sourceId: string): void {
    this.selectedSourceId.set(sourceId);
  }

  toggleSyncHistoryRow(syncId: string | number): void {
    const syncKey = String(syncId);
    const next = new Set(this.syncHistoryExpanded());
    if (next.has(syncKey)) {
      next.delete(syncKey);
    } else {
      next.add(syncKey);
    }
    this.syncHistoryExpanded.set(next);
  }

  syncHistoryEntryDetails(syncId: string): SyncHistoryDetailEntry[] {
    return this.syncHistoryEntryDetailsById().get(syncId) ?? [];
  }

  recomputeHistoryEntryDetails(recomputeId: string): RecomputeHistoryDetailEntry[] {
    return this.recomputeHistoryEntryDetailsById().get(recomputeId) ?? [];
  }

  async refreshSources(): Promise<void> {
    await this.store.refreshSources();
  }

  private ensureAdminAction(): boolean {
    if (this.canAdmin()) {
      return true;
    }
    this.snackBar.open('Read-only mode. Only global Admin can modify sources or run sync.', 'Close', {
      duration: 3500
    });
    return false;
  }

  isEditing(sourceId: string): boolean {
    return this.configDrafts().has(sourceId);
  }

  draftFor(sourceId: string): OsvConfigDraft | undefined {
    return this.configDrafts().get(sourceId);
  }

  startEdit(source: MalwareSource): void {
    if (!this.ensureAdminAction()) {
      return;
    }
    if (this.configDrafts().has(source.id)) {
      return;
    }
    const draft = buildOsvConfigDraft(source);
    this.configDrafts.set(mapSetValue(this.configDrafts(), source.id, draft));
  }

  cancelEdit(sourceId: string): void {
    this.configDrafts.set(mapDeleteValue(this.configDrafts(), sourceId));
  }

  updateDraftField(sourceId: string, field: keyof OsvConfigDraft, event: Event): void {
    const draft = this.configDrafts().get(sourceId);
    if (!draft) {
      return;
    }
    const target = event.target as HTMLInputElement | null;
    const nextValue = target?.value ?? '';
    const next: OsvConfigDraft = { ...draft, [field]: nextValue };
    this.configDrafts.set(mapSetValue(this.configDrafts(), sourceId, next));
  }

  async saveDraft(sourceId: string): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    const draft = this.configDrafts().get(sourceId);
    if (!draft) {
      return;
    }
    const payload = buildOsvUpdatePayload(draft);
    await this.store.updateSource(sourceId, payload);
    this.configDrafts.set(mapDeleteValue(this.configDrafts(), sourceId));
  }

  async toggleSource(source: MalwareSource, nextValue: boolean): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    await this.store.updateSource(source.id, { isActive: nextValue });
  }

  async triggerFullSync(): Promise<void> {
    const source = this.selectedSource();
    if (!source) {
      return;
    }
    await this.triggerFullSyncForSource(source);
  }

  async triggerLatestSync(): Promise<void> {
    const source = this.selectedSource();
    if (!source) {
      return;
    }
    await this.triggerLatestSyncForSource(source);
  }

  async triggerFullSyncForSource(source: MalwareSource): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    this.selectedSourceId.set(source.id);
    await this.store.ensureSyncHistory(source.id);

    const result = await this.store.triggerFullSync();
    if (!result) {
      this.snackBar.open('Failed to start full sync.', 'Close', { duration: 3500 });
      return;
    }
    this.startSyncHistoryKickRefreshWindow();
    void this.store.refreshSources(true);
    await this.store.refreshSyncHistory(source.id);
  }

  async triggerLatestSyncForSource(source: MalwareSource): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    this.selectedSourceId.set(source.id);
    await this.store.ensureSyncHistory(source.id);

    const result = await this.store.triggerLatestSync();
    if (!result) {
      this.snackBar.open('Failed to start latest sync.', 'Close', { duration: 3500 });
      return;
    }
    this.startSyncHistoryKickRefreshWindow();
    void this.store.refreshSources(true);
    await this.store.refreshSyncHistory(source.id);
  }

  private startSyncHistoryKickRefreshWindow(): void {
    this.syncHistoryKickRefresh.set(true);
    if (this.syncHistoryKickRefreshTimer !== null) {
      window.clearTimeout(this.syncHistoryKickRefreshTimer);
    }
    this.syncHistoryKickRefreshTimer = window.setTimeout(() => {
      this.syncHistoryKickRefresh.set(false);
      this.syncHistoryKickRefreshTimer = null;
    }, syncHistoryAutoRefreshStaleMs);
  }

  async recomputeSummaries(): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    const result = await this.store.recomputeAllActiveTestMalwareSummaries();
    if (!result) {
      this.snackBar.open('Failed to enqueue summary recomputation.', 'Close', { duration: 3500 });
      return;
    }
    this.recomputeHistoryMode.set('summaries');
    await this.store.refreshSummaryRecomputeHistory();
  }

  sourceResultsRecomputeLoadState(sourceId: string): LoadState {
    return this.store.getSourceResultsRecomputeStatus(sourceId);
  }

  async recomputeSourceResults(source: MalwareSource): Promise<void> {
    if (!this.ensureAdminAction()) {
      return;
    }
    this.selectedSourceId.set(source.id);
    this.recomputeHistoryMode.set('source');
    await this.store.ensureSourceResultsRecomputeHistory(source.id);

    const result = await this.store.recomputeSourceResults(source.id);
    if (!result) {
      this.snackBar.open('Failed to start results recomputation.', 'Close', { duration: 3500 });
      return;
    }
    await this.store.refreshSourceResultsRecomputeHistory(source.id);
  }

  setRecomputeHistoryMode(value: unknown): void {
    if (value === 'summaries') {
      this.recomputeHistoryMode.set('summaries');
      return;
    }
    this.recomputeHistoryMode.set('source');
  }

  async loadRecomputeHistory(): Promise<void> {
    const mode = this.recomputeHistoryMode();
    if (mode === 'summaries') {
      await this.store.ensureSummaryRecomputeHistory();
      return;
    }
    const sourceId = this.selectedSourceId();
    if (!sourceId) {
      return;
    }
    await this.store.ensureSourceResultsRecomputeHistory(sourceId);
  }

  async refreshRecomputeHistory(): Promise<void> {
    const mode = this.recomputeHistoryMode();
    if (mode === 'summaries') {
      await this.store.refreshSummaryRecomputeHistory();
      return;
    }
    const sourceId = this.selectedSourceId();
    if (!sourceId) {
      return;
    }
    await this.store.refreshSourceResultsRecomputeHistory(sourceId);
  }

  async loadFindings(sourceId: string): Promise<void> {
    this.selectedSourceId.set(sourceId);
    await this.store.ensureFindings(sourceId);
  }

  async refreshSelectedFindings(): Promise<void> {
    const sourceId = this.selectedSourceId();
    if (!sourceId) {
      return;
    }
    await this.store.refreshFindings(sourceId);
  }

  async loadSyncHistory(sourceId: string): Promise<void> {
    await this.store.ensureSyncHistory(sourceId);
  }

  async refreshSyncHistory(): Promise<void> {
    const sourceId = this.selectedSourceId();
    if (!sourceId) {
      return;
    }
    await this.store.refreshSyncHistory(sourceId);
  }

  toggleFindingsRow(rowId: string | number): void {
    const key = String(rowId);
    const next = new Set(this.findingsExpanded());
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    this.findingsExpanded.set(next);
  }

  toggleRecomputeHistoryRow(rowId: string | number): void {
    const key = String(rowId);
    const next = new Set(this.recomputeHistoryExpanded());
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    this.recomputeHistoryExpanded.set(next);
  }

  setRecomputeHistoryFilter(event: Event): void {
    const target = event.target as HTMLInputElement | null;
    this.recomputeHistoryFilter.set(target?.value ?? '');
  }

  setSyncHistoryFilter(event: Event): void {
    const target = event.target as HTMLInputElement | null;
    this.syncHistoryFilter.set(target?.value ?? '');
  }

  private getTableBindings(kind: SourcesTableKind): SourcesTableBindings {
    switch (kind) {
      case 'findings':
        return this.tableBindings.findings;
      case 'syncHistory':
        return this.tableBindings.syncHistory;
      case 'recomputeHistory':
        return this.tableBindings.recomputeHistory;
      default:
        return this.tableBindings.findings;
    }
  }

  toggleTablePanel(kind: SourcesTableKind): void {
    togglePanel(this.getTableBindings(kind).tablePanelOpen);
  }

  toggleFilterPanel(kind: SourcesTableKind): void {
    togglePanel(this.getTableBindings(kind).filterPanelOpen);
  }

  setFilterModeFor(kind: SourcesTableKind, key: string, mode: FilterMode): void {
    const state = this.getTableBindings(kind);
    applyFilterMode(state.filterMode, state.columnFilters, key, mode);
  }

  setMultiFilterFor(kind: SourcesTableKind, key: string, values: string[]): void {
    applyMultiFilter(this.getTableBindings(kind).multiFilters, key, values);
  }

  setFilterValueFor(kind: SourcesTableKind, key: string, value: string): void {
    const state = this.getTableBindings(kind);
    applyFilterValue((k, mode) => this.setFilterModeFor(kind, k, mode), state.columnFilters, key, value);
  }

  clearFiltersFor(kind: SourcesTableKind): void {
    const state = this.getTableBindings(kind);
    clearTableFilters(state, state.columns, state.advancedKeys);
  }

  setColumnQueryFor(kind: SourcesTableKind, event: Event): void {
    setTableColumnQuery(this.getTableBindings(kind).columnQuery, event);
  }

  addColumnFor(kind: SourcesTableKind, key: string): void {
    const state = this.getTableBindings(kind);
    addTableColumn(state.columnOrder, state.columnQuery, key);
  }

  removeColumnFor(kind: SourcesTableKind, key: string): void {
    removeTableColumn(this.getTableBindings(kind).columnOrder, key);
  }

  dropColumnFor(kind: SourcesTableKind, event: CdkDragDrop<string[]>): void {
    dropTableColumn(this.getTableBindings(kind).columnOrder, event);
  }

  setPageSizeFor(kind: SourcesTableKind, size: number): void {
    const state = this.getTableBindings(kind);
    setTablePageSize(state.pageSize, state.pageIndex, size);
  }

  prevPageFor(kind: SourcesTableKind): void {
    prevTablePage(this.getTableBindings(kind).pageIndex);
  }

  nextPageFor(kind: SourcesTableKind): void {
    const state = this.getTableBindings(kind);
    nextTablePage(state.pageIndex, state.totalPages());
  }

  configValue(source: MalwareSource, key: string): string {
    return sourceConfigValue(source, key);
  }

  isOsvMirrorSource(source: MalwareSource): boolean {
    return source.sourceType.toUpperCase() === 'OSV_MIRROR';
  }

  readonly findingsRowValueForTable = (row: unknown, key: string): string => {
    if (!row || typeof row !== 'object') {
      return '-';
    }
    return findingDisplayValue(row as ScanComponentResult, key);
  };

  readonly findingsExpandedDetailsForTable = (row: unknown) => this.findingsExpandedItems(row);

  readonly recomputeHistoryRowValueForTable = (row: unknown, key: string): string => {
    if (!row || typeof row !== 'object') {
      return '-';
    }
    return recomputeHistoryValue(row as RecomputeHistoryRow, key);
  };

  readonly syncHistoryRowValueForTable = (row: unknown, key: string): string => {
    if (!row || typeof row !== 'object') {
      return '-';
    }
    return syncHistoryValue(row as SyncHistoryRow, key);
  };

  toggleFilterFor(kind: SourcesTableKind, payload: { key: string; event: Event }): void {
    toggleTableFilterVisibility(this.getTableBindings(kind).filterVisible, payload);
  }

  setColumnFilterFor(kind: SourcesTableKind, payload: { key: string; event: Event }): void {
    const state = this.getTableBindings(kind);
    setTableColumnFilter((key, mode) => this.setFilterModeFor(kind, key, mode), state.columnFilters, payload);
  }

  toggleSortFor(kind: SourcesTableKind, key: string): void {
    const state = this.getTableBindings(kind);
    toggleTableSortState(state.sortColumn, state.sortDir, key);
  }

}
