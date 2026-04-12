
import { CdkDragDrop } from '@angular/cdk/drag-drop';
import { ChangeDetectionStrategy, Component, DestroyRef, ErrorHandler, computed, effect, inject, signal, untracked } from '@angular/core';
import { ActivatedRoute, ParamMap, Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { MatTooltipModule } from '@angular/material/tooltip';
import { Check, ExternalLink, Filter, LucideAngularModule, RefreshCw, XCircle } from 'lucide-angular';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { fromEvent, interval, merge } from 'rxjs';
import { ProjectContextService } from '../../../projects/data-access/project-context.service';
import { DataApi } from '../../../data/data-access/data.api';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { CopyBlockComponent } from '../../../../shared/ui/copy-block/copy-block.component';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
  AdvancedFilterPanelComponent
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import { DataTableExpandedDetailsComponent } from '../../../../shared/ui/data-table/data-table-expanded-details.component';
import { buildExtendedFilterQueryParams, readExtendedFilterQueryParams } from '../../../../shared/utils/extended-filter-routing';
import { AlertsApi, AlertGroupsListQuery, AlertOccurrencesListQuery } from '../../data-access/alerts.api';
import {
  AlertDetectionMode,
  AlertDetectionModeState,
  AlertDedupRule,
  AlertDedupScope,
  AlertGroup,
  AlertMinSeverity,
  AlertOccurrence,
  AlertingConnectorState,
  PutAlertDetectionModesRequest,
  PutAlertDedupRulesRequest
} from '../../data-access/alerts.types';
import { LoadState } from '../../../../shared/types/load-state';
import {
  ALL_CATEGORIES,
  GROUP_COLUMNS,
  GROUP_COLUMN_KEYS,
  GroupColumnKey,
  OCCURRENCE_COLUMNS,
  OCCURRENCE_COLUMN_KEYS,
  OccurrenceColumnKey
} from './security-alerts.tables';
import {
  dedupRuleOptionLabel as buildDedupRuleOptionLabel,
  connectorRouteIds,
  dedupTargetSummary as buildDedupTargetSummary,
  dedupRuleIdentity,
  isKnownKey,
  isNilUUID,
  normalizeDedupRules,
  normalizeMinSeverity,
  normalizeOptionalID,
  occurrenceDetectionData,
  serializeDedupRules,
} from './security-alerts.utils';
import {
  buildBooleanRecord,
  buildModeRecord,
  buildMultiRecord,
  buildStringRecord,
  toggleExpandedRowId,
  SortDirection,
} from './security-alerts.table-state';
import {
  addColumn as addTableColumn,
  clearFilters as clearTableFilters,
  dropColumn as dropTableColumn,
  nextPage as nextTablePage,
  prevPage as prevTablePage,
  removeColumn as removeTableColumn,
  SecurityAlertsTableBindings,
  setColumnFilter as setTableColumnFilter,
  setFilterMode as setTableFilterMode,
  setFilterValue as setTableFilterValue,
  setMultiFilter as setTableMultiFilter,
  setPageSize as setTablePageSize,
  toggleColumnFilter as toggleTableColumnFilter,
  toggleFilterPanel as toggleTableFilterPanel,
  toggleSort as toggleTableSort,
  toggleTablePanel as toggleTablePanelOpen,
} from './security-alerts.table-actions';
import {
  acknowledgeActionTooltip,
  alertGroupExpandedItems,
  alertGroupValue,
  alertOccurrenceDetailsJson,
  alertOccurrenceExpandedItems,
  alertOccurrenceValue,
  alertSeverityClass,
  alertStatusClass,
  AlertGroupFilterState,
  AlertOccurrenceFilterState,
  applyGroupFiltersAndSort,
  applyOccurrenceFiltersAndSort,
  closeActionTooltip,
  isMalwareAlertGroup,
  isMalwareAlertOccurrence,
} from './security-alerts.mapper';
import {
  acknowledgeAlertGroup,
  closeAlertGroup,
  MALWARE_SUMMARY_TABLE_ID,
  openGroupInExplorer as openGroupInExplorerOperation,
  openOccurrenceInExplorer,
} from './security-alerts.operations';
import { exportAllGroups as exportAlertGroups, exportAllOccurrences as exportAlertOccurrences } from './security-alerts.export';
import {
  buildGroupAdvancedFields,
  buildGroupFilterOptions,
  buildOccurrenceAdvancedFields,
  buildOccurrenceFilterOptions,
  groupValueForTable,
  occurrenceValueForTable,
} from './security-alerts.view';
const DEDUP_MIN_SEVERITY_OPTIONS: AlertMinSeverity[] = ['INFO', 'WARNING', 'ERROR'];
const DETECTION_MODE_SEVERITY_OPTIONS: AlertMinSeverity[] = ['ERROR', 'WARNING', 'INFO'];
const DETECTION_MODE_ORDER: AlertDetectionMode[] = ['PURL_VERSION_SMART', 'PURL_CONTAINS_PREFIX'];
const GROUP_STATUS_UI_VALUES = ['OPEN', 'CLOSED'] as const;
const GROUP_STATUS_UI_SET = new Set<string>(GROUP_STATUS_UI_VALUES);
const GROUP_STATUS_BACKEND_VALUES: NonNullable<AlertGroupsListQuery['status']> = [
  'OPEN',
  'ACKNOWLEDGED',
  'CLOSED'
];
const GROUP_STATUS_BACKEND_SET = new Set<string>(GROUP_STATUS_BACKEND_VALUES);
const ALERTS_GROUPS_TABLE_ID = 'alerts_groups';
const ALERTS_OCCURRENCES_TABLE_ID = 'alerts_occurrences';

function buildDefaultGroupFilterModeRecord(): Record<GroupColumnKey, AdvancedFilterMode> {
  return {
    ...buildModeRecord(GROUP_COLUMN_KEYS, 'contains'),
    status: 'select'
  };
}

function buildDefaultGroupMultiFilterRecord(): Record<GroupColumnKey, string[]> {
  return {
    ...buildMultiRecord(GROUP_COLUMN_KEYS),
    status: ['OPEN']
  };
}

type AlertsTableKind = 'groups' | 'occurrences';
type DedupScopeBuilderOption = AlertDedupScope | 'ALL';
type AlertDetectionModeFormState = {
  mode: AlertDetectionMode;
  enabled: boolean;
  severity: AlertMinSeverity;
};

@Component({
  selector: 'app-security-alerts',
  imports: [
    MatCardModule,
    MatButtonModule,
    MatCheckboxModule,
    MatFormFieldModule,
    MatSelectModule,
    MatTooltipModule,
    LucideAngularModule,
    DataTableComponent,
    AdvancedFilterPanelComponent,
    LoadingIndicatorComponent,
    CopyBlockComponent,
    DataTableExpandedDetailsComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './security-alerts.component.html',
  styleUrl: './security-alerts.component.scss'
})
export class SecurityAlertsComponent {
  protected readonly RefreshCw = RefreshCw;
  protected readonly Filter = Filter;
  protected readonly ExternalLink = ExternalLink;
  protected readonly Check = Check;
  protected readonly XCircle = XCircle;

  protected readonly groupColumns = GROUP_COLUMNS;
  protected readonly occurrenceColumns = OCCURRENCE_COLUMNS;
  protected readonly categories = ALL_CATEGORIES;
  protected readonly groupPageSizeOptions = [10, 25, 50, 100];
  protected readonly occurrencePageSizeOptions = [10, 25, 50, 100];

  private readonly api = inject(AlertsApi);
  private readonly dataApi = inject(DataApi);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly errorHandler = inject(ErrorHandler);
  private readonly destroyRef = inject(DestroyRef);
  private readonly projectContext = inject(ProjectContextService);
  private silentRefreshInFlight = false;
  private applyingUrlFilters = false;

  readonly isAdmin = computed(() => this.projectContext.canAdmin());

  // --------------------------
  // Alert groups (batched)
  // --------------------------
  readonly groupsStatus = signal<LoadState>('idle');
  readonly groupsError = signal<string | null>(null);
  readonly groups = signal<AlertGroup[]>([]);
  readonly groupsTotal = signal(0);
  readonly groupsExpanded = signal<Set<string>>(new Set());

  readonly groupsPageIndex = signal(0);
  readonly groupsPageSize = signal(50);
  readonly groupsTotalPages = computed(() => {
    const size = this.groupsPageSize();
    if (size <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(this.groupsTotal() / size));
  });

  readonly groupsColumnOrder = signal<GroupColumnKey[]>([
    'severity',
    'status',
    'category',
    'type',
    'detectionMode',
    'detectionData',
    'dedupRule',
    'title',
    'occurrences',
    'lastSeenAt'
  ]);
  readonly groupsLockedColumns: GroupColumnKey[] = ['title'];
  readonly groupsTablePanelOpen = signal(false);
  readonly groupsFilterPanelOpen = signal(false);
  readonly groupsFilterVisible = signal<Record<GroupColumnKey, boolean>>(
    buildBooleanRecord(GROUP_COLUMN_KEYS)
  );
  readonly groupsColumnFilters = signal<Record<GroupColumnKey, string>>(
    buildStringRecord(GROUP_COLUMN_KEYS)
  );
  readonly groupsFilterMode = signal<Record<GroupColumnKey, AdvancedFilterMode>>(
    buildDefaultGroupFilterModeRecord()
  );
  readonly groupsMultiFilters = signal<Record<GroupColumnKey, string[]>>(
    buildDefaultGroupMultiFilterRecord()
  );
  readonly groupsFilterRowVisible = computed(() => Object.values(this.groupsFilterVisible()).some(Boolean));
  readonly groupsSortColumn = signal<GroupColumnKey | null>('lastSeenAt');
  readonly groupsSortDir = signal<SortDirection>('desc');
  readonly groupsAvailableColumns = computed(() => {
    const selected = new Set(this.groupsColumnOrder());
    return this.groupColumns.filter((c) => !selected.has(c.key as GroupColumnKey));
  });
  readonly groupDetectionDataById = computed<ReadonlyMap<string, string>>(() => {
    const byID = new Map<string, string>();
    for (const occurrence of this.occurrences()) {
      const groupID = (occurrence.groupId ?? '').trim();
      if (!groupID || byID.has(groupID)) {
        continue;
      }
      byID.set(groupID, occurrenceDetectionData(occurrence.details, occurrence.entityRef));
    }
    return byID;
  });
  readonly groupsFilterOptions = computed<Record<GroupColumnKey, string[]>>(() =>
    buildGroupFilterOptions(this.groups(), this.groupDetectionDataById())
  );
  readonly groupsAdvancedFields = computed<AdvancedFilterField[]>(() =>
    buildGroupAdvancedFields(
      this.groupsFilterMode(),
      this.groupsColumnFilters(),
      this.groupsMultiFilters(),
      this.groupsFilterOptions()
    )
  );

  // Server query snapshot (drives backend calls). We keep this minimal and rely on shared table
  // extended filtering for UI filtering (same pattern as Data feature).
  private readonly groupsAppliedQuery = signal<AlertGroupsListQuery>({
    page: 1,
    pageSize: 50,
    status: ['OPEN']
  });

  // Export provider for DataTable (server paging + local filters).
  readonly exportAllGroups = async (): Promise<AlertGroup[]> =>
    exportAlertGroups(this.api, this.groupsAppliedQuery(), this.groupFilterState());

  // --------------------------
  // Alert occurrences (append-only)
  // --------------------------
  readonly occurrencesStatus = signal<LoadState>('idle');
  readonly occurrencesError = signal<string | null>(null);
  readonly occurrences = signal<AlertOccurrence[]>([]);
  readonly occurrencesTotal = signal(0);

  readonly occurrencesPageIndex = signal(0);
  readonly occurrencesPageSize = signal(50);
  readonly occurrencesTotalPages = computed(() => {
    const size = this.occurrencesPageSize();
    if (size <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(this.occurrencesTotal() / size));
  });

  readonly occurrencesColumnOrder = signal<OccurrenceColumnKey[]>([
    'severity',
    'category',
    'type',
    'detectionMode',
    'detectionData',
    'title',
    'occurredAt',
    'entityRef'
  ]);
  readonly occurrencesLockedColumns: OccurrenceColumnKey[] = ['entityRef'];
  readonly occurrencesTablePanelOpen = signal(false);
  readonly occurrencesFilterPanelOpen = signal(false);
  readonly occurrencesFilterVisible = signal<Record<OccurrenceColumnKey, boolean>>(
    buildBooleanRecord(OCCURRENCE_COLUMN_KEYS)
  );
  readonly occurrencesColumnFilters = signal<Record<OccurrenceColumnKey, string>>(
    buildStringRecord(OCCURRENCE_COLUMN_KEYS)
  );
  readonly occurrencesFilterMode = signal<Record<OccurrenceColumnKey, AdvancedFilterMode>>(
    buildModeRecord(OCCURRENCE_COLUMN_KEYS, 'contains')
  );
  readonly occurrencesMultiFilters = signal<Record<OccurrenceColumnKey, string[]>>(
    buildMultiRecord(OCCURRENCE_COLUMN_KEYS)
  );
  readonly occurrencesFilterRowVisible = computed(() => Object.values(this.occurrencesFilterVisible()).some(Boolean));
  readonly occurrencesSortColumn = signal<OccurrenceColumnKey | null>('occurredAt');
  readonly occurrencesSortDir = signal<SortDirection>('desc');
  readonly occurrencesAvailableColumns = computed(() => {
    const selected = new Set(this.occurrencesColumnOrder());
    return this.occurrenceColumns.filter((c) => !selected.has(c.key as OccurrenceColumnKey));
  });
  readonly occurrencesFilterOptions = computed<Record<OccurrenceColumnKey, string[]>>(() =>
    buildOccurrenceFilterOptions(this.occurrences())
  );
  readonly occurrencesAdvancedFields = computed<AdvancedFilterField[]>(() =>
    buildOccurrenceAdvancedFields(
      this.occurrencesFilterMode(),
      this.occurrencesColumnFilters(),
      this.occurrencesMultiFilters(),
      this.occurrencesFilterOptions()
    )
  );

  // Server query snapshot (drives backend calls).
  private readonly occurrencesAppliedQuery = signal<AlertOccurrencesListQuery>({
    page: 1,
    pageSize: 50
  });

  // Expandable rows for occurrences.
  readonly occurrencesExpanded = signal<Set<string>>(new Set());

  readonly groupsTableRows = computed(() =>
    applyGroupFiltersAndSort(this.groups(), this.groupFilterState())
  );
  readonly occurrencesTableRows = computed(() =>
    applyOccurrenceFiltersAndSort(this.occurrences(), this.occurrenceFilterState())
  );

  readonly groupValue = (row: AlertGroup, key: GroupColumnKey): string =>
    alertGroupValue(row, key, { groupDetectionDataById: this.groupDetectionDataById() });
  readonly occurrenceValue = alertOccurrenceValue;
  readonly severityClass = alertSeverityClass;
  readonly statusClass = alertStatusClass;
  readonly isMalwareGroup = isMalwareAlertGroup;
  readonly isMalwareOccurrence = isMalwareAlertOccurrence;
  readonly occurrenceDetailsJson = alertOccurrenceDetailsJson;
  readonly groupExpandedItems = (row: AlertGroup) =>
    alertGroupExpandedItems(row, { groupDetectionDataById: this.groupDetectionDataById() });
  readonly occurrenceExpandedItems = alertOccurrenceExpandedItems;
  readonly acknowledgeTooltip = (row: AlertGroup): string =>
    acknowledgeActionTooltip(row, this.isAdmin());
  readonly closeTooltip = (row: AlertGroup): string =>
    closeActionTooltip(row, this.isAdmin());
  readonly groupExpandedDetailsForTable = (row: unknown) =>
    alertGroupExpandedItems(row as AlertGroup, { groupDetectionDataById: this.groupDetectionDataById() });
  readonly occurrenceExpandedDetailsForTable = (row: unknown) =>
    alertOccurrenceExpandedItems(row as AlertOccurrence);

  // Export provider for DataTable (server paging + local filters).
  readonly exportAllOccurrences = async (): Promise<AlertOccurrence[]> =>
    exportAlertOccurrences(this.api, this.occurrencesAppliedQuery(), this.occurrenceFilterState());

  readonly catalogStatus = signal<LoadState>('idle');
  readonly catalogError = signal<string | null>(null);
  readonly products = signal<Array<{ id: string; name: string }>>([]);
  readonly scopes = signal<Array<{ id: string; name: string }>>([]);
  readonly tests = signal<Array<{ id: string; name: string }>>([]);
  readonly canManageDetectionModes = computed(() => this.projectContext.canWrite());
  readonly detectionModesStatus = signal<LoadState>('idle');
  readonly detectionModesError = signal<string | null>(null);
  readonly detectionModes = signal<AlertDetectionModeFormState[]>([]);
  readonly detectionModesSavedSnapshot = signal<AlertDetectionModeFormState[]>([]);
  readonly detectionModesSaving = signal(false);
  readonly detectionModeSeverityOptions = DETECTION_MODE_SEVERITY_OPTIONS;
  readonly detectionModesDirty = computed(() => {
    return this.serializeDetectionModes(this.detectionModes()) !== this.serializeDetectionModes(this.detectionModesSavedSnapshot());
  });
  readonly detectionModeCode = (mode: AlertDetectionMode): string => {
    if (mode === 'PURL_VERSION_SMART') {
      return 'purl_version_smart';
    }
    return 'purl_contains_prefix';
  };
  readonly detectionModeDescription = (mode: AlertDetectionMode): string => {
    if (mode === 'PURL_VERSION_SMART') {
      return 'Primary match mode: exact PURL+version when available, fallback to prefix for unknown versions.';
    }
    return 'Prediction mode: prefix/base PURL matching for broader suspicious-package coverage.';
  };
  readonly canManageDedupRules = computed(() => this.projectContext.canWrite());

  readonly dedupRulesStatus = signal<LoadState>('idle');
  readonly dedupRulesError = signal<string | null>(null);
  readonly dedupRules = signal<AlertDedupRule[]>([]);
  readonly dedupRulesSavedSnapshot = signal<AlertDedupRule[]>([]);
  readonly persistedDedupRules = computed(() =>
    this.dedupRules().filter((rule) => !isNilUUID(rule.id))
  );
  readonly dedupSaving = signal(false);
  readonly dedupMinSeverityOptions = DEDUP_MIN_SEVERITY_OPTIONS;
  readonly dedupScopeOptions: DedupScopeBuilderOption[] = ['ALL', 'PRODUCT', 'SCOPE', 'TEST'];
  readonly dedupNewScope = signal<DedupScopeBuilderOption>('ALL');
  readonly dedupNewMinSeverity = signal<AlertMinSeverity>('INFO');
  readonly dedupNewProductId = signal('');
  readonly dedupNewScopeId = signal('');
  readonly dedupNewTestId = signal('');
  readonly dedupDirty = computed(() => {
    return serializeDedupRules(this.dedupRules()) !== serializeDedupRules(this.dedupRulesSavedSnapshot());
  });
  readonly canManageJiraRouting = computed(() => this.projectContext.canAdmin());
  readonly jiraConnectorStatus = signal<LoadState>('idle');
  readonly jiraConnectorError = signal<string | null>(null);
  readonly jiraConnector = signal<AlertingConnectorState | null>(null);
  readonly jiraDedupRuleBinding = signal('');
  readonly jiraDedupRuleBindingSaved = signal('');
  readonly jiraBindingSaving = signal(false);
  readonly jiraBindingDirty = computed(() => this.jiraDedupRuleBinding() !== this.jiraDedupRuleBindingSaved());

  constructor() {
    this.route.queryParamMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => this.applyFilterStateFromUrl(params));

    // Reload everything when project changes.
    let lastProjectId: string | null = null;
    effect(() => {
      const pid = this.projectContext.selectedProjectId();
      if (!pid || pid === lastProjectId) {
        return;
      }
      lastProjectId = pid;
      this.resetToDefaults();
      // Tables are refreshed by query-driven effects above; here we only refresh config panels.
      void Promise.all([this.refreshDetectionModes(true), this.refreshDedupRules(true), this.refreshJiraConnector(true)]);
    });

    // Sync backend group status query with status multi-select filter.
    effect(() => {
      const mode = this.groupsFilterMode().status;
      const selectedStatuses = this.groupsMultiFilters().status;
      const nextStatus: NonNullable<AlertGroupsListQuery['status']> =
        mode === 'select'
          ? this.mapGroupStatusSelectionToBackendQuery(selectedStatuses)
          : ['OPEN'];

      const current = this.groupsAppliedQuery();
      const currentStatus = this.normalizeGroupBackendStatusFilters(current.status);
      if (this.groupStatusFiltersEqual(currentStatus, nextStatus)) {
        return;
      }

      this.groupsAppliedQuery.set({
        ...current,
        page: 1,
        status: nextStatus
      });
      this.groupsPageIndex.set(0);
    });

    // Keep advanced filter state mirrored in URL query params.
    effect(() => {
      this.groupsFilterMode();
      this.groupsColumnFilters();
      this.groupsMultiFilters();
      this.occurrencesFilterMode();
      this.occurrencesColumnFilters();
      this.occurrencesMultiFilters();
      if (this.applyingUrlFilters) {
        return;
      }
      this.syncFilterStateToUrl();
    });

    // Fetch groups when applied query or pagination changes.
    effect(() => {
      const q = this.groupsAppliedQuery();
      const pageIndex = this.groupsPageIndex();
      const pageSize = this.groupsPageSize();
      void this.loadGroups({ ...q, page: pageIndex + 1, pageSize });
    });

    // Fetch occurrences when applied query or pagination changes.
    effect(() => {
      const q = this.occurrencesAppliedQuery();
      const pageIndex = this.occurrencesPageIndex();
      const pageSize = this.occurrencesPageSize();
      void this.loadOccurrences({ ...q, page: pageIndex + 1, pageSize });
    });

    // Background refresh (lightweight, no spinner flip).
    interval(60_000)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        if (this.groupsStatus() !== 'loaded' && this.occurrencesStatus() !== 'loaded') {
          return;
        }
        void this.refreshAll(false);
      });

    // Refresh silently after returning to this browser tab/window.
    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
      merge(fromEvent(window, 'focus'), fromEvent(document, 'visibilitychange'))
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe(() => {
          if (document.hidden) {
            return;
          }
          void this.refreshAll(false);
        });
    }
  }

  async refreshAll(forceSpinner: boolean): Promise<void> {
    if (!forceSpinner && this.silentRefreshInFlight) {
      return;
    }
    if (!forceSpinner) {
      this.silentRefreshInFlight = true;
    }
    try {
      await Promise.all([
        this.refreshAlertsTable('groups', forceSpinner),
        this.refreshAlertsTable('occurrences', forceSpinner),
        this.refreshDetectionModes(forceSpinner),
        this.refreshDedupRules(forceSpinner),
        this.refreshJiraConnector(forceSpinner)
      ]);
    } finally {
      if (!forceSpinner) {
        this.silentRefreshInFlight = false;
      }
    }
  }

  async refreshDetectionModes(forceSpinner: boolean): Promise<void> {
    const hadLoaded = untracked(() => this.detectionModesStatus()) === 'loaded';
    if (forceSpinner || !hadLoaded) {
      this.detectionModesStatus.set('loading');
      this.detectionModesError.set(null);
    }
    try {
      const items = await this.api.listAlertDetectionModes();
      const normalized = this.normalizeDetectionModes(items ?? []);
      this.detectionModes.set(normalized);
      this.detectionModesSavedSnapshot.set(normalized);
      this.detectionModesStatus.set('loaded');
    } catch (error) {
      if (!forceSpinner && hadLoaded) {
        return;
      }
      this.errorHandler.handleError(error);
      this.detectionModesStatus.set('error');
      this.detectionModesError.set('Failed to load alert detection modes.');
    }
  }

  setDetectionModeEnabled(mode: AlertDetectionMode, enabled: boolean): void {
    if (!this.canManageDetectionModes()) {
      return;
    }
    this.detectionModes.update((items) =>
      items.map((item) => (item.mode === mode ? { ...item, enabled } : item))
    );
  }

  setDetectionModeSeverity(mode: AlertDetectionMode, value: string): void {
    if (!this.canManageDetectionModes()) {
      return;
    }
    const severity = this.normalizeDetectionModeSeverity(value);
    this.detectionModes.update((items) =>
      items.map((item) => (item.mode === mode ? { ...item, severity } : item))
    );
  }

  async saveDetectionModes(): Promise<void> {
    if (!this.canManageDetectionModes() || this.detectionModesSaving() || !this.detectionModesDirty()) {
      return;
    }
    this.detectionModesSaving.set(true);
    this.detectionModesError.set(null);
    try {
      const payload: PutAlertDetectionModesRequest = {
        modes: this.detectionModes().map((item) => ({
          mode: item.mode,
          enabled: item.enabled,
          severity: item.severity
        }))
      };
      const saved = await this.api.putAlertDetectionModes(payload);
      const normalized = this.normalizeDetectionModes(saved ?? []);
      this.detectionModes.set(normalized);
      this.detectionModesSavedSnapshot.set(normalized);
      await this.refreshAlertsTable('groups', true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.detectionModesError.set('Failed to save alert detection modes.');
    } finally {
      this.detectionModesSaving.set(false);
    }
  }

  async refreshDedupRules(forceSpinner: boolean): Promise<void> {
    const hadLoaded = untracked(() => this.dedupRulesStatus()) === 'loaded';
    if (this.catalogStatus() === 'idle') {
      await this.loadCatalog();
    }
    if (forceSpinner || !hadLoaded) {
      this.dedupRulesStatus.set('loading');
      this.dedupRulesError.set(null);
    }
    try {
      const items = await this.api.listAlertDedupRules('malware.detected');
      const normalized = normalizeDedupRules((items ?? []).filter((rule) => this.isPersistableDedupRule(rule)));
      this.dedupRules.set(normalized);
      this.dedupRulesSavedSnapshot.set(normalized);
      this.dedupRulesStatus.set('loaded');
    } catch (error) {
      if (!forceSpinner && hadLoaded) {
        return;
      }
      this.errorHandler.handleError(error);
      this.dedupRulesStatus.set('error');
      this.dedupRulesError.set('Failed to load deduplication rules.');
    }
  }

  async refreshJiraConnector(forceSpinner: boolean): Promise<void> {
    const hadLoaded = untracked(() => this.jiraConnectorStatus()) === 'loaded';
    if (forceSpinner || !hadLoaded) {
      this.jiraConnectorStatus.set('loading');
      this.jiraConnectorError.set(null);
    }
    try {
      const connectors = await this.api.getAlertingConnectors();
      const jira = (connectors ?? []).find((item) => (item.type ?? '').toLowerCase() === 'jira') ?? null;
      this.jiraConnector.set(jira);
      const binding = (jira?.jiraDedupRuleId ?? '').trim();
      this.jiraDedupRuleBinding.set(binding);
      this.jiraDedupRuleBindingSaved.set(binding);
      this.jiraConnectorStatus.set('loaded');
    } catch (error) {
      if (!forceSpinner && hadLoaded) {
        return;
      }
      this.errorHandler.handleError(error);
      this.jiraConnectorStatus.set('error');
      this.jiraConnectorError.set('Failed to load Jira alert routing.');
    }
  }

  private async loadCatalog(): Promise<void> {
    this.catalogStatus.set('loading');
    this.catalogError.set(null);
    try {
      const [products, scopes, tests] = await Promise.all([
        this.dataApi.getProducts(),
        this.dataApi.getAllScopes(),
        this.dataApi.getAllTests()
      ]);
      this.products.set((products ?? []).map((p) => ({ id: p.id, name: p.name })));
      this.scopes.set((scopes ?? []).map((s) => ({ id: s.id, name: s.name })));
      this.tests.set((tests ?? []).map((t) => ({ id: t.id, name: t.name })));
      this.catalogStatus.set('loaded');
    } catch (error) {
      this.errorHandler.handleError(error);
      this.catalogStatus.set('error');
      this.catalogError.set('Failed to load routing catalog.');
    }
  }

  readonly dedupTargetSummary = (rule: AlertDedupRule): string =>
    buildDedupTargetSummary(rule, this.products(), this.scopes(), this.tests());

  addDedupRule(): void {
    if (!this.canManageDedupRules()) {
      return;
    }
    const selectedScope = this.dedupNewScope();
    const scope = this.toRuleDedupScope(selectedScope);
    const productId = selectedScope === 'PRODUCT' ? normalizeOptionalID(this.dedupNewProductId()) : '';
    const scopeId = selectedScope === 'SCOPE' ? normalizeOptionalID(this.dedupNewScopeId()) : '';
    const testId = selectedScope === 'TEST' ? normalizeOptionalID(this.dedupNewTestId()) : '';
    if (
      (selectedScope === 'PRODUCT' && !productId) ||
      (selectedScope === 'SCOPE' && !scopeId) ||
      (selectedScope === 'TEST' && !testId)
    ) {
      this.dedupRulesError.set('Select a target for PRODUCT/SCOPE/TEST dedup scope.');
      return;
    }

    const projectId = this.projectContext.selectedProjectId() ?? '';
    const nextRule: AlertDedupRule = {
      id: `local-${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`,
      projectId,
      alertType: 'malware.detected',
      dedupScope: scope,
      minSeverity: normalizeMinSeverity(this.dedupNewMinSeverity()),
      productId: productId || null,
      scopeId: scopeId || null,
      testId: testId || null,
      enabled: true
    };
    const nextKey = dedupRuleIdentity(nextRule);
    const current = this.dedupRules();
    if (current.some((item) => dedupRuleIdentity(item) === nextKey)) {
      this.dedupRulesError.set('This dedup rule already exists.');
      return;
    }

    this.dedupRulesError.set(null);
    this.dedupRules.set(normalizeDedupRules([...current, nextRule]));
  }

  setDedupRuleMinSeverity(rule: AlertDedupRule, value: string): void {
    if (!this.canManageDedupRules()) {
      return;
    }
    const target = dedupRuleIdentity(rule);
    const minSeverity = normalizeMinSeverity(value);
    const next = this.dedupRules().map((item) =>
      dedupRuleIdentity(item) === target ? { ...item, minSeverity } : item
    );
    this.dedupRules.set(normalizeDedupRules(next));
  }

  removeDedupRule(rule: AlertDedupRule): void {
    if (!this.canManageDedupRules()) {
      return;
    }
    const target = dedupRuleIdentity(rule);
    const next = this.dedupRules().filter((item) => dedupRuleIdentity(item) !== target);
    this.dedupRules.set(normalizeDedupRules(next));
  }

  async saveDedupRules(): Promise<void> {
    if (!this.canManageDedupRules() || this.dedupSaving()) {
      return;
    }
    this.dedupSaving.set(true);
    this.dedupRulesError.set(null);
    try {
      const rules = this.dedupRules()
        .map((rule) => this.toPutDedupRule(rule))
        .filter((rule): rule is PutAlertDedupRulesRequest['rules'][number] => rule !== null);
      const saved = await this.api.putAlertDedupRules({ rules }, 'malware.detected');
      const normalized = normalizeDedupRules(saved ?? []);
      this.dedupRules.set(normalized);
      this.dedupRulesSavedSnapshot.set(normalized);
      await this.refreshAlertsTable('groups', true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.dedupRulesError.set('Failed to save deduplication rules.');
    } finally {
      this.dedupSaving.set(false);
    }
  }

  readonly dedupRuleOptionLabel = (rule: AlertDedupRule): string =>
    buildDedupRuleOptionLabel(rule, this.products(), this.scopes(), this.tests());

  private isPersistableDedupRule(rule: AlertDedupRule): boolean {
    const dedupScope = (rule.dedupScope ?? 'GLOBAL') as AlertDedupScope;
    const productId = normalizeOptionalID(rule.productId);
    const scopeId = normalizeOptionalID(rule.scopeId);
    const testId = normalizeOptionalID(rule.testId);
    if (dedupScope === 'GLOBAL') {
      return !productId && !scopeId && !testId;
    }
    if (dedupScope === 'PRODUCT') {
      return !!productId && !scopeId && !testId;
    }
    if (dedupScope === 'SCOPE') {
      return !productId && !!scopeId && !testId;
    }
    if (dedupScope === 'TEST') {
      return !productId && !scopeId && !!testId;
    }
    return false;
  }

  private toPutDedupRule(rule: AlertDedupRule): PutAlertDedupRulesRequest['rules'][number] | null {
    if (!this.isPersistableDedupRule(rule)) {
      return null;
    }
    return {
      dedupScope: rule.dedupScope,
      minSeverity: normalizeMinSeverity(rule.minSeverity ?? 'INFO'),
      productId: normalizeOptionalID(rule.productId),
      scopeId: normalizeOptionalID(rule.scopeId),
      testId: normalizeOptionalID(rule.testId),
      enabled: rule.enabled
    };
  }

  private toRuleDedupScope(scope: DedupScopeBuilderOption): AlertDedupScope {
    if (scope === 'ALL') {
      return 'GLOBAL';
    }
    return scope;
  }

  private normalizeDetectionModes(items: AlertDetectionModeState[]): AlertDetectionModeFormState[] {
    const defaults = new Map<AlertDetectionMode, AlertDetectionModeFormState>([
      [
        'PURL_VERSION_SMART',
        {
          mode: 'PURL_VERSION_SMART',
          enabled: true,
          severity: 'ERROR'
        }
      ],
      [
        'PURL_CONTAINS_PREFIX',
        {
          mode: 'PURL_CONTAINS_PREFIX',
          enabled: false,
          severity: 'WARNING'
        }
      ]
    ]);

    for (const raw of items) {
      const mode = (raw?.mode ?? '').trim().toUpperCase();
      if (!this.isDetectionMode(mode)) {
        continue;
      }
      defaults.set(mode, {
        mode,
        enabled: !!raw.enabled,
        severity: this.normalizeDetectionModeSeverity(raw.severity)
      });
    }

    return DETECTION_MODE_ORDER.map((mode) => defaults.get(mode)!).map((item) => ({ ...item }));
  }

  private isDetectionMode(value: string): value is AlertDetectionMode {
    return value === 'PURL_VERSION_SMART' || value === 'PURL_CONTAINS_PREFIX';
  }

  private normalizeDetectionModeSeverity(value: string): AlertMinSeverity {
    const normalized = (value ?? '').trim().toUpperCase();
    if (normalized === 'ERROR') {
      return 'ERROR';
    }
    if (normalized === 'WARN' || normalized === 'WARNING') {
      return 'WARNING';
    }
    return 'INFO';
  }

  private serializeDetectionModes(items: AlertDetectionModeFormState[]): string {
    return [...items]
      .sort((left, right) => this.detectionModeSortRank(left.mode) - this.detectionModeSortRank(right.mode))
      .map((item) => `${item.mode}:${item.enabled ? '1' : '0'}:${item.severity}`)
      .join('|');
  }

  private detectionModeSortRank(mode: AlertDetectionMode): number {
    if (mode === 'PURL_VERSION_SMART') {
      return 1;
    }
    if (mode === 'PURL_CONTAINS_PREFIX') {
      return 2;
    }
    return 100;
  }

  private normalizeGroupStatusSelection(values: readonly string[] | undefined): Array<(typeof GROUP_STATUS_UI_VALUES)[number]> {
    const normalized: Array<(typeof GROUP_STATUS_UI_VALUES)[number]> = [];
    for (const item of values ?? []) {
      let value = (item ?? '').trim().toUpperCase();
      if (value === 'ACKNOWLEDGED') {
        value = 'CLOSED';
      }
      if (!GROUP_STATUS_UI_SET.has(value)) {
        continue;
      }
      const status = value as (typeof GROUP_STATUS_UI_VALUES)[number];
      if (!normalized.includes(status)) {
        normalized.push(status);
      }
    }
    return normalized;
  }

  private normalizeGroupBackendStatusFilters(
    values: readonly string[] | undefined
  ): NonNullable<AlertGroupsListQuery['status']> {
    const normalized: NonNullable<AlertGroupsListQuery['status']> = [];
    for (const item of values ?? []) {
      const value = (item ?? '').trim().toUpperCase();
      if (!GROUP_STATUS_BACKEND_SET.has(value)) {
        continue;
      }
      const status = value as NonNullable<AlertGroupsListQuery['status']>[number];
      if (!normalized.includes(status)) {
        normalized.push(status);
      }
    }
    return normalized;
  }

  private mapGroupStatusSelectionToBackendQuery(
    values: readonly string[] | undefined
  ): NonNullable<AlertGroupsListQuery['status']> {
    const selected = this.normalizeGroupStatusSelection(values);
    if (selected.length === 0) {
      return ['OPEN'];
    }

    const mapped: NonNullable<AlertGroupsListQuery['status']> = [];
    if (selected.includes('OPEN')) {
      mapped.push('OPEN');
    }
    if (selected.includes('CLOSED')) {
      // Backward compatibility: historical ACKNOWLEDGED rows are grouped under CLOSED view.
      mapped.push('CLOSED', 'ACKNOWLEDGED');
    }
    return mapped;
  }

  private groupStatusFiltersEqual(
    left: readonly string[] | undefined,
    right: readonly string[] | undefined
  ): boolean {
    const leftNorm = this.normalizeGroupBackendStatusFilters(left);
    const rightNorm = this.normalizeGroupBackendStatusFilters(right);
    if (leftNorm.length !== rightNorm.length) {
      return false;
    }
    return leftNorm.every((value) => rightNorm.includes(value));
  }

  private isDefaultGroupStatusSelection(values: readonly string[]): boolean {
    return values.length === 1 && values[0] === 'OPEN';
  }

  private normalizeSelectValues(values: readonly string[] | undefined): string[] {
    const normalized: string[] = [];
    for (const item of values ?? []) {
      const value = (item ?? '').trim();
      if (!value || normalized.includes(value)) {
        continue;
      }
      normalized.push(value);
    }
    return normalized;
  }

  private normalizeSelectValuesForGroupKey(key: GroupColumnKey, values: readonly string[] | undefined): string[] {
    if (key === 'status') {
      return this.normalizeGroupStatusSelection(values);
    }
    return this.normalizeSelectValues(values);
  }

  private applyFilterStateFromUrl(params: ParamMap): void {
    this.applyingUrlFilters = true;
    try {
      this.applyGroupsFilterStateFromUrl(params);
      this.applyOccurrencesFilterStateFromUrl(params);
    } finally {
      this.applyingUrlFilters = false;
    }
  }

  private applyGroupsFilterStateFromUrl(params: ParamMap): void {
    const parsed = readExtendedFilterQueryParams<GroupColumnKey>(params, {
      tableId: ALERTS_GROUPS_TABLE_ID,
      keys: GROUP_COLUMN_KEYS
    });

    const nextMode = buildDefaultGroupFilterModeRecord();
    const nextValues = buildStringRecord(GROUP_COLUMN_KEYS);
    const nextMulti = buildDefaultGroupMultiFilterRecord();
    const nextVisible = buildBooleanRecord(GROUP_COLUMN_KEYS);

    for (const key of GROUP_COLUMN_KEYS) {
      const parsedMode = parsed.mode[key];
      if (key === 'status') {
        const sourceValues =
          parsedMode === 'select'
            ? parsed.values.status
            : (parsed.value.status ?? '').trim()
              ? [parsed.value.status ?? '']
              : [];
        const statusSelection = this.normalizeSelectValuesForGroupKey('status', sourceValues);
        nextMode.status = 'select';
        nextMulti.status = statusSelection.length > 0 ? statusSelection : ['OPEN'];
        nextVisible.status = !this.isDefaultGroupStatusSelection(nextMulti.status);
        continue;
      }

      if (parsedMode === 'select') {
        const selected = this.normalizeSelectValuesForGroupKey(key, parsed.values[key]);
        nextMode[key] = 'select';
        nextMulti[key] = selected;
        nextVisible[key] = selected.length > 0;
        continue;
      }

      if (parsedMode === 'contains') {
        const value = (parsed.value[key] ?? '').trim();
        nextMode[key] = 'contains';
        nextValues[key] = value;
        nextVisible[key] = value !== '';
      }
    }

    this.groupsFilterMode.set(nextMode);
    this.groupsColumnFilters.set(nextValues);
    this.groupsMultiFilters.set(nextMulti);
    this.groupsFilterVisible.set(nextVisible);
    this.groupsFilterPanelOpen.set(parsed.hasAny);
  }

  private applyOccurrencesFilterStateFromUrl(params: ParamMap): void {
    const parsed = readExtendedFilterQueryParams<OccurrenceColumnKey>(params, {
      tableId: ALERTS_OCCURRENCES_TABLE_ID,
      keys: OCCURRENCE_COLUMN_KEYS
    });

    const nextMode = buildModeRecord(OCCURRENCE_COLUMN_KEYS, 'contains');
    const nextValues = buildStringRecord(OCCURRENCE_COLUMN_KEYS);
    const nextMulti = buildMultiRecord(OCCURRENCE_COLUMN_KEYS);
    const nextVisible = buildBooleanRecord(OCCURRENCE_COLUMN_KEYS);

    for (const key of OCCURRENCE_COLUMN_KEYS) {
      const parsedMode = parsed.mode[key];
      if (parsedMode === 'select') {
        const selected = this.normalizeSelectValues(parsed.values[key]);
        nextMode[key] = 'select';
        nextMulti[key] = selected;
        nextVisible[key] = selected.length > 0;
        continue;
      }
      if (parsedMode === 'contains') {
        const value = (parsed.value[key] ?? '').trim();
        nextMode[key] = 'contains';
        nextValues[key] = value;
        nextVisible[key] = value !== '';
      }
    }

    this.occurrencesFilterMode.set(nextMode);
    this.occurrencesColumnFilters.set(nextValues);
    this.occurrencesMultiFilters.set(nextMulti);
    this.occurrencesFilterVisible.set(nextVisible);
    this.occurrencesFilterPanelOpen.set(parsed.hasAny);
  }

  private syncFilterStateToUrl(): void {
    const current = this.route.snapshot.queryParams as Record<string, unknown>;
    const next: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(current)) {
      if (this.isAlertsFilterQueryParam(key)) {
        continue;
      }
      next[key] = value;
    }

    const groupsQuery = this.buildGroupRoutingFilterQuery();
    const occurrencesQuery = this.buildOccurrenceRoutingFilterQuery();
    const combinedQuery = { ...groupsQuery, ...occurrencesQuery };
    for (const [key, value] of Object.entries(combinedQuery)) {
      if (typeof value !== 'string' || value.trim() === '') {
        continue;
      }
      next[key] = value;
    }

    if (this.queryParamsSignature(current) === this.queryParamsSignature(next)) {
      return;
    }

    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: next,
      replaceUrl: true
    });
  }

  private buildGroupRoutingFilterQuery(): Record<string, string | null> {
    const mode = this.groupsFilterMode();
    const values = this.groupsColumnFilters();
    const selected = this.groupsMultiFilters();
    const filters: Partial<Record<GroupColumnKey, { mode?: AdvancedFilterMode; value?: string; values?: string[] }>> = {};

    for (const key of GROUP_COLUMN_KEYS) {
      if (key === 'status') {
        if (mode.status !== 'select') {
          continue;
        }
        const normalizedStatusSelection = this.normalizeSelectValuesForGroupKey('status', selected.status);
        if (normalizedStatusSelection.length === 0 || this.isDefaultGroupStatusSelection(normalizedStatusSelection)) {
          continue;
        }
        filters.status = { mode: 'select', values: normalizedStatusSelection };
        continue;
      }

      if (mode[key] === 'select') {
        const selectedValues = this.normalizeSelectValuesForGroupKey(key, selected[key]);
        if (selectedValues.length === 0) {
          continue;
        }
        filters[key] = { mode: 'select', values: selectedValues };
        continue;
      }

      const value = (values[key] ?? '').trim();
      if (!value) {
        continue;
      }
      filters[key] = { mode: 'contains', value };
    }

    return buildExtendedFilterQueryParams(ALERTS_GROUPS_TABLE_ID, filters);
  }

  private buildOccurrenceRoutingFilterQuery(): Record<string, string | null> {
    const mode = this.occurrencesFilterMode();
    const values = this.occurrencesColumnFilters();
    const selected = this.occurrencesMultiFilters();
    const filters: Partial<Record<OccurrenceColumnKey, { mode?: AdvancedFilterMode; value?: string; values?: string[] }>> = {};

    for (const key of OCCURRENCE_COLUMN_KEYS) {
      if (mode[key] === 'select') {
        const selectedValues = this.normalizeSelectValues(selected[key]);
        if (selectedValues.length === 0) {
          continue;
        }
        filters[key] = { mode: 'select', values: selectedValues };
        continue;
      }
      const value = (values[key] ?? '').trim();
      if (!value) {
        continue;
      }
      filters[key] = { mode: 'contains', value };
    }

    return buildExtendedFilterQueryParams(ALERTS_OCCURRENCES_TABLE_ID, filters);
  }

  private isAlertsFilterQueryParam(key: string): boolean {
    const normalized = key.trim();
    return normalized.startsWith('ef_alerts_groups_') || normalized.startsWith('ef_alerts_occurrences_');
  }

  private queryParamsSignature(params: Record<string, unknown>): string {
    const keys = Object.keys(params).sort((left, right) => left.localeCompare(right));
    return keys
      .map((key) => `${key}=${this.queryParamValueSignature(params[key])}`)
      .join('&');
  }

  private queryParamValueSignature(value: unknown): string {
    if (Array.isArray(value)) {
      return value.map((entry) => String(entry)).join(',');
    }
    if (value === null || value === undefined) {
      return '';
    }
    return String(value);
  }

  async saveJiraDedupBinding(): Promise<void> {
    if (!this.canManageJiraRouting() || this.jiraBindingSaving()) {
      return;
    }
    const jira = this.jiraConnector();
    if (!jira) {
      this.jiraConnectorError.set('Jira connector routing was not found.');
      return;
    }

    const jiraDedupRuleId = normalizeOptionalID(this.jiraDedupRuleBinding());
    if (jira.alertingEnabled && !jiraDedupRuleId) {
      this.jiraConnectorError.set('Enabled Jira routing requires a dedup rule binding.');
      return;
    }

    this.jiraBindingSaving.set(true);
    this.jiraConnectorError.set(null);
    try {
      await this.api.upsertAlertingConnector('jira', {
        enabled: !!jira.alertingEnabled,
        jiraDedupRuleId: jiraDedupRuleId || null,
        routes: {
          productIds: connectorRouteIds(jira, 'PRODUCT'),
          scopeIds: connectorRouteIds(jira, 'SCOPE'),
          testIds: connectorRouteIds(jira, 'TEST')
        }
      });
      this.jiraDedupRuleBindingSaved.set(jiraDedupRuleId);
      await this.refreshJiraConnector(false);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.jiraConnectorError.set('Failed to save Jira dedup rule binding.');
    } finally {
      this.jiraBindingSaving.set(false);
    }
  }

  // --------------------------
  // Table actions / glue
  // --------------------------
  toggleTablePanel(kind: AlertsTableKind): void {
    toggleTablePanelOpen(this.getTableBindings(kind));
  }

  dropColumn(kind: AlertsTableKind, event: CdkDragDrop<string[]>): void {
    dropTableColumn(this.getTableBindings(kind), event);
  }

  removeColumn(kind: AlertsTableKind, key: string): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    removeTableColumn(this.getTableBindings(kind), key);
  }

  addColumn(kind: AlertsTableKind, key: string): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    addTableColumn(this.getTableBindings(kind), key);
  }

  toggleExtendedFilters(kind: AlertsTableKind): void {
    toggleTableFilterPanel(this.getTableBindings(kind));
  }

  setFilterMode(kind: AlertsTableKind, key: string, mode: AdvancedFilterMode): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    setTableFilterMode(this.getTableBindings(kind), key, mode);
  }

  setFilterValue(kind: AlertsTableKind, key: string, value: string): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    setTableFilterValue(this.getTableBindings(kind), key, value);
  }

  setMultiFilter(kind: AlertsTableKind, key: string, values: string[]): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    setTableMultiFilter(this.getTableBindings(kind), key, values);
  }

  clearFilters(kind: AlertsTableKind): void {
    clearTableFilters(this.getTableBindings(kind));
    if (kind !== 'groups') {
      return;
    }
    this.groupsFilterMode.update((state) => ({
      ...state,
      status: 'select'
    }));
    this.groupsMultiFilters.update((state) => ({
      ...state,
      status: ['OPEN']
    }));
  }

  toggleFilter(kind: AlertsTableKind, payload: { key: string; event: Event }): void {
    if (!this.isTableColumnKey(kind, payload.key)) {
      return;
    }
    toggleTableColumnFilter(this.getTableBindings(kind), payload);
  }

  setColumnFilter(kind: AlertsTableKind, payload: { key: string; event: Event }): void {
    if (!this.isTableColumnKey(kind, payload.key)) {
      return;
    }
    setTableColumnFilter(this.getTableBindings(kind), payload);
  }

  toggleSort(kind: AlertsTableKind, key: string): void {
    if (!this.isTableColumnKey(kind, key)) {
      return;
    }
    toggleTableSort(this.getTableBindings(kind), key);
  }

  setPageSize(kind: AlertsTableKind, size: number): void {
    setTablePageSize(this.getTableBindings(kind), size);
  }

  prevPage(kind: AlertsTableKind): void {
    prevTablePage(this.getTableBindings(kind));
  }

  nextPage(kind: AlertsTableKind): void {
    nextTablePage(this.getTableBindings(kind), this.totalPagesFor(kind));
  }

  toggleRow(kind: AlertsTableKind, id: string | number): void {
    if (kind === 'groups') {
      this.groupsExpanded.update((expanded) => toggleExpandedRowId(expanded, id));
      return;
    }
    this.occurrencesExpanded.update((expanded) => toggleExpandedRowId(expanded, id));
  }

  async openGroupInExplorer(row: AlertGroup): Promise<void> {
    if (!this.isMalwareGroup(row)) {
      return;
    }
    await openGroupInExplorerOperation(this.router, row, MALWARE_SUMMARY_TABLE_ID);
  }

  async acknowledgeGroup(row: AlertGroup): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    if (this.isMalwareGroup(row)) {
      return;
    }
    await this.runGroupMutation(
      () => acknowledgeAlertGroup(this.api, row.id),
      'Failed to acknowledge alert group.'
    );
  }

  async closeGroup(row: AlertGroup): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    if (this.isMalwareGroup(row)) {
      return;
    }
    await this.runGroupMutation(
      () => closeAlertGroup(this.api, row.id),
      'Failed to close alert group.'
    );
  }

  openInExplorer(row: AlertOccurrence): void {
    if (!this.isMalwareOccurrence(row)) {
      return;
    }
    void openOccurrenceInExplorer(this.router, row, MALWARE_SUMMARY_TABLE_ID);
  }

  private async runGroupMutation(action: () => Promise<void>, errorMessage: string): Promise<void> {
    try {
      await action();
      await this.refreshAlertsTable('groups', true);
    } catch (error) {
      this.errorHandler.handleError(error);
      this.groupsError.set(errorMessage);
    }
  }

  // --------------------------
  // Templates helpers
  // --------------------------
  readonly groupValueForTable = (row: AlertGroup, key: string): string =>
    groupValueForTable(row, key, this.groupDetectionDataById());
  readonly occurrenceValueForTable = occurrenceValueForTable;

  readonly groupValueForExpandedDetails = (row: unknown, key: string): string =>
    this.groupValueForTable(row as AlertGroup, key);

  readonly occurrenceValueForExpandedDetails = (row: unknown, key: string): string =>
    this.occurrenceValueForTable(row as AlertOccurrence, key);

  // --------------------------
  // Backend fetch
  // --------------------------
  private async loadGroups(q: AlertGroupsListQuery, forceSpinner = true): Promise<void> {
    const hadLoaded = untracked(() => this.groupsStatus()) === 'loaded';
    if (forceSpinner || !hadLoaded) {
      this.groupsStatus.set('loading');
      this.groupsError.set(null);
    }
    try {
      const payload = await this.api.listGroups(q);
      this.groups.set(payload.items ?? []);
      this.groupsTotal.set(typeof payload.total === 'number' ? payload.total : 0);
      this.groupsStatus.set('loaded');
    } catch (error) {
      if (!forceSpinner && hadLoaded) {
        return;
      }
      this.errorHandler.handleError(error);
      this.groupsStatus.set('error');
      this.groupsError.set('Failed to load alert groups.');
    }
  }

  private async loadOccurrences(q: AlertOccurrencesListQuery, forceSpinner = true): Promise<void> {
    const hadLoaded = untracked(() => this.occurrencesStatus()) === 'loaded';
    if (forceSpinner || !hadLoaded) {
      this.occurrencesStatus.set('loading');
      this.occurrencesError.set(null);
    }
    try {
      const payload = await this.api.listOccurrences(q);
      this.occurrences.set(payload.items ?? []);
      this.occurrencesTotal.set(typeof payload.total === 'number' ? payload.total : 0);
      this.occurrencesStatus.set('loaded');
    } catch (error) {
      if (!forceSpinner && hadLoaded) {
        return;
      }
      this.errorHandler.handleError(error);
      this.occurrencesStatus.set('error');
      this.occurrencesError.set('Failed to load alert occurrences.');
    }
  }

  private async refreshAlertsTable(kind: AlertsTableKind, forceSpinner: boolean): Promise<void> {
    if (kind === 'groups') {
      const q = this.groupsAppliedQuery();
      await this.loadGroups(
        { ...q, page: this.groupsPageIndex() + 1, pageSize: this.groupsPageSize() },
        forceSpinner
      );
      return;
    }
    const q = this.occurrencesAppliedQuery();
    await this.loadOccurrences(
      { ...q, page: this.occurrencesPageIndex() + 1, pageSize: this.occurrencesPageSize() },
      forceSpinner
    );
  }

  private getTableBindings(kind: AlertsTableKind): SecurityAlertsTableBindings {
    if (kind === 'groups') {
      return {
        keys: GROUP_COLUMN_KEYS as readonly string[],
        lockedColumns: this.groupsLockedColumns as readonly string[],
        tablePanelOpen: this.groupsTablePanelOpen,
        filterPanelOpen: this.groupsFilterPanelOpen,
        columnOrder: this.groupsColumnOrder as unknown as SecurityAlertsTableBindings['columnOrder'],
        filterVisible: this.groupsFilterVisible as unknown as SecurityAlertsTableBindings['filterVisible'],
        columnFilters: this.groupsColumnFilters as unknown as SecurityAlertsTableBindings['columnFilters'],
        filterMode: this.groupsFilterMode as unknown as SecurityAlertsTableBindings['filterMode'],
        multiFilters: this.groupsMultiFilters as unknown as SecurityAlertsTableBindings['multiFilters'],
        sortColumn: this.groupsSortColumn as unknown as SecurityAlertsTableBindings['sortColumn'],
        sortDir: this.groupsSortDir as unknown as SecurityAlertsTableBindings['sortDir'],
        pageSize: this.groupsPageSize,
        pageIndex: this.groupsPageIndex
      };
    }
    return {
      keys: OCCURRENCE_COLUMN_KEYS as readonly string[],
      lockedColumns: this.occurrencesLockedColumns as readonly string[],
      tablePanelOpen: this.occurrencesTablePanelOpen,
      filterPanelOpen: this.occurrencesFilterPanelOpen,
      columnOrder: this.occurrencesColumnOrder as unknown as SecurityAlertsTableBindings['columnOrder'],
      filterVisible: this.occurrencesFilterVisible as unknown as SecurityAlertsTableBindings['filterVisible'],
      columnFilters: this.occurrencesColumnFilters as unknown as SecurityAlertsTableBindings['columnFilters'],
      filterMode: this.occurrencesFilterMode as unknown as SecurityAlertsTableBindings['filterMode'],
      multiFilters: this.occurrencesMultiFilters as unknown as SecurityAlertsTableBindings['multiFilters'],
      sortColumn: this.occurrencesSortColumn as unknown as SecurityAlertsTableBindings['sortColumn'],
      sortDir: this.occurrencesSortDir as unknown as SecurityAlertsTableBindings['sortDir'],
      pageSize: this.occurrencesPageSize,
      pageIndex: this.occurrencesPageIndex
    };
  }

  private isTableColumnKey(kind: AlertsTableKind, key: string): boolean {
    const keys = kind === 'groups' ? GROUP_COLUMN_KEYS : OCCURRENCE_COLUMN_KEYS;
    return isKnownKey(key, keys);
  }

  private totalPagesFor(kind: AlertsTableKind): number {
    return kind === 'groups' ? this.groupsTotalPages() : this.occurrencesTotalPages();
  }

  private groupFilterState(): AlertGroupFilterState {
    return {
      filters: this.groupsColumnFilters(),
      modes: this.groupsFilterMode(),
      selected: this.groupsMultiFilters(),
      sortColumn: this.groupsSortColumn(),
      sortDirection: this.groupsSortDir(),
      groupDetectionDataById: this.groupDetectionDataById(),
    };
  }

  private occurrenceFilterState(): AlertOccurrenceFilterState {
    return {
      filters: this.occurrencesColumnFilters(),
      modes: this.occurrencesFilterMode(),
      selected: this.occurrencesMultiFilters(),
      sortColumn: this.occurrencesSortColumn(),
      sortDirection: this.occurrencesSortDir(),
    };
  }

  private resetToDefaults(): void {
    this.groupsAppliedQuery.set({
      page: 1,
      pageSize: this.groupsPageSize(),
      status: ['OPEN']
    });
    this.groupsPageIndex.set(0);
    this.groupsFilterVisible.set(buildBooleanRecord(GROUP_COLUMN_KEYS));
    this.groupsColumnFilters.set(buildStringRecord(GROUP_COLUMN_KEYS));
    this.groupsFilterMode.set(buildDefaultGroupFilterModeRecord());
    this.groupsMultiFilters.set(buildDefaultGroupMultiFilterRecord());

    this.occurrencesAppliedQuery.set({
      page: 1,
      pageSize: this.occurrencesPageSize()
    });
    this.occurrencesPageIndex.set(0);

    this.detectionModesStatus.set('idle');
    this.detectionModesError.set(null);
    this.detectionModes.set([]);
    this.detectionModesSavedSnapshot.set([]);
    this.detectionModesSaving.set(false);
  }
}
