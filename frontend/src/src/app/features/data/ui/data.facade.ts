import { DestroyRef, ErrorHandler, computed, effect, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { ActivatedRoute, ParamMap, Router } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { firstValueFrom } from 'rxjs';
import {
  COMPONENT_COLUMNS,
  COMPONENT_DEFAULT_COLUMNS,
  LAST_CHANGE_COLUMNS,
  PRODUCT_COLUMNS,
  REVISION_CHANGE_COLUMNS,
  REVISION_COLUMNS,
  SCOPE_COLUMNS,
  TEST_COLUMNS,
  ComponentColumnFilterKey,
  ComponentColumnKey,
  LastChangeColumnKey,
  ProductColumnKey,
  RevisionChangeColumnKey,
  RevisionColumnKey,
  ScopeColumnKey,
  TestColumnKey
} from './data.columns';
import { ConfirmDialogComponent } from '../../../shared/ui/confirm-dialog/confirm-dialog.component';
import { NamePromptDialogComponent } from '../../../shared/ui/name-prompt-dialog/name-prompt-dialog.component';
import { JiraEntitySettingsDialogComponent } from './jira-entity-settings-dialog/jira-entity-settings-dialog.component';
import { DataStore } from '../state/data.store';
import { DataApi } from '../data-access/data.api';
import { MalwareAnalysisApi } from '../data-access/malware-analysis.api';
import { ComponentAnalysisQueueItem, MalwareResultSummary } from '../data-access/malware-analysis.types';
import {
  ComponentSummary,
  DataSection,
  ProductSummary,
  ScopeSummary,
  TestRevisionChangeSummary,
  TestRevisionFindingDiff,
  TestRevisionSummary,
  TestSummary
} from '../data-access/data.types';
import { ClipboardService } from '../../../core/clipboard/clipboard.service';
import { ProjectContextService } from '../../projects/data-access/project-context.service';
import { LoadState } from '../../../shared/types/load-state';
import {
  filterComponentRows,
  DataComponentFilterState
} from './data-component-filter.utils';
import { mapSetValue } from '../../../shared/utils/map-utils';
import {
  addOption,
  anyFilterValue,
  anyFilterVisible,
  appendFilterParams,
  availableColumns,
  columnLabel,
  enableAllVisibility,
  filterByColumns,
  orderedColumns,
  paginate,
  readInputValue,
  setFilterValue,
  sortOptions,
  sortRows,
  toggleSort,
  toggleVisibility,
  visibilityFromValues,
} from './data-table.utils';
import {
  extractLicenseValues,
  formatLicensesDetail as formatLicensesDetailValue,
  hasLicenses as hasLicensesValue
} from './data-licenses.utils';

type ExpandState = Set<string>;

type SectionItem = ProductSummary | ScopeSummary | TestSummary;

const componentPreviewLimit = 5;

export abstract class DataFacade {
  private readonly store = inject(DataStore);
  private readonly api = inject(DataApi);
  private readonly malwareApi = inject(MalwareAnalysisApi);
  private readonly projectContext = inject(ProjectContextService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly destroyRef = inject(DestroyRef);
  private readonly errorHandler = inject(ErrorHandler);
  private readonly dialog = inject(MatDialog);
  private readonly snackBar = inject(MatSnackBar);
  private readonly clipboard = inject(ClipboardService);

  readonly canWrite = computed(() => this.projectContext.canWrite());
  readonly isAdmin = computed(() => this.projectContext.canAdmin());
  readonly isMutating = signal(false);

  readonly section = signal<DataSection>('products');
  readonly selectedProductId = signal<string | null>(null);
  readonly selectedScopeId = signal<string | null>(null);
  readonly selectedTestId = signal<string | null>(null);
  readonly isTestDetail = signal(false);
  // Optional deep-link support: when set, load Components in Test detail using server-side `q`
  // so the target component is visible without requiring "Load all".
  readonly componentQ = signal('');
  private isSyncingFromUrl = false;
  private lastSyncedParams = '';
  private lastRefreshContextKey = '';
  private lastComponentsTestId: string | null = null;
  private readonly lastComponentQByTest = new Map<string, string>();
  private revisionChangesPollHandle: ReturnType<typeof window.setInterval> | null = null;
  private revisionChangesPollTestId: string | null = null;

  readonly productSortColumn = signal<ProductColumnKey>('updated');
  readonly productSortDir = signal<'asc' | 'desc'>('desc');
  readonly productPageIndex = signal(0);
  readonly productPageSize = signal(25);
  readonly productColumnFilters = signal<{ name: string; scopes: string; updated: string }>({
    name: '',
    scopes: '',
    updated: ''
  });
  readonly productFilterMode = signal<{ name: 'contains' | 'select'; scopes: 'contains' | 'select'; updated: 'contains' | 'select' }>({
    name: 'contains',
    scopes: 'contains',
    updated: 'contains'
  });
  readonly productMultiFilters = signal<{ name: string[]; scopes: string[]; updated: string[] }>({
    name: [],
    scopes: [],
    updated: []
  });
  readonly productFilterVisible = signal<{ name: boolean; scopes: boolean; updated: boolean }>({
    name: false,
    scopes: false,
    updated: false
  });
  readonly productFilterPanelOpen = signal(false);
  readonly productFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.productFilterVisible()) ||
      anyFilterValue(this.productColumnFilters())
  );
  readonly productFilterOptions = computed(() => {
    const options = {
      name: new Set<string>(),
      scopes: new Set<string>(),
      updated: new Set<string>()
    };
    for (const product of this.products().slice(0, 500)) {
      const scopesCount = this.store.getScopesCount(product.id);
      const name = this.productColumnValue(product, 'name');
      const scopes = this.productColumnValue({ ...product, scopesCount }, 'scopes');
      const updated = this.productColumnValue(product, 'updated');
      addOption(options.name, name);
      addOption(options.scopes, scopes);
      addOption(options.updated, updated);
    }
    return {
      name: sortOptions(options.name),
      scopes: sortOptions(options.scopes),
      updated: sortOptions(options.updated)
    };
  });

  readonly scopeSortColumn = signal<ScopeColumnKey>('updated');
  readonly scopeSortDir = signal<'asc' | 'desc'>('desc');
  readonly scopePageIndex = signal(0);
  readonly scopePageSize = signal(25);
  readonly scopeColumnFilters = signal<{ name: string; tests: string; updated: string }>({
    name: '',
    tests: '',
    updated: ''
  });
  readonly scopeFilterMode = signal<{ name: 'contains' | 'select'; tests: 'contains' | 'select'; updated: 'contains' | 'select' }>({
    name: 'contains',
    tests: 'contains',
    updated: 'contains'
  });
  readonly scopeMultiFilters = signal<{ name: string[]; tests: string[]; updated: string[] }>({
    name: [],
    tests: [],
    updated: []
  });
  readonly scopeFilterVisible = signal<{ name: boolean; tests: boolean; updated: boolean }>({
    name: false,
    tests: false,
    updated: false
  });
  readonly scopeFilterPanelOpen = signal(false);
  readonly scopeFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.scopeFilterVisible()) ||
      anyFilterValue(this.scopeColumnFilters())
  );
  readonly scopeFilterOptions = computed(() => {
    const options = {
      name: new Set<string>(),
      tests: new Set<string>(),
      updated: new Set<string>()
    };
    for (const scope of this.scopes().slice(0, 500)) {
      const testsCount = this.store.getTestsCount(scope.id);
      const name = this.scopeColumnValue(scope, 'name');
      const tests = this.scopeColumnValue({ ...scope, testsCount }, 'tests');
      const updated = this.scopeColumnValue(scope, 'updated');
      addOption(options.name, name);
      addOption(options.tests, tests);
      addOption(options.updated, updated);
    }
    return {
      name: sortOptions(options.name),
      tests: sortOptions(options.tests),
      updated: sortOptions(options.updated)
    };
  });

  readonly testSortColumn = signal<TestColumnKey>('updated');
  readonly testSortDir = signal<'asc' | 'desc'>('desc');
  readonly testPageIndex = signal(0);
  readonly testPageSize = signal(25);
  readonly testColumnFilters = signal<{ name: string; id: string; components: string; updated: string }>({
    name: '',
    id: '',
    components: '',
    updated: ''
  });
  readonly testFilterMode = signal<{
    name: 'contains' | 'select';
    id: 'contains' | 'select';
    components: 'contains' | 'select';
    updated: 'contains' | 'select';
  }>({
    name: 'contains',
    id: 'contains',
    components: 'contains',
    updated: 'contains'
  });
  readonly testMultiFilters = signal<{ name: string[]; id: string[]; components: string[]; updated: string[] }>({
    name: [],
    id: [],
    components: [],
    updated: []
  });
  readonly testFilterVisible = signal<{ name: boolean; id: boolean; components: boolean; updated: boolean }>({
    name: false,
    id: false,
    components: false,
    updated: false
  });
  readonly testFilterPanelOpen = signal(false);
  readonly testFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.testFilterVisible()) ||
      anyFilterValue(this.testColumnFilters())
  );
  readonly testFilterOptions = computed(() => {
    const options = {
      name: new Set<string>(),
      id: new Set<string>(),
      components: new Set<string>(),
      updated: new Set<string>()
    };
    for (const test of this.tests().slice(0, 500)) {
      const componentsCount = this.store.getComponentsCount(test.id);
      const name = this.testColumnValue(test, 'name');
      const id = this.testColumnValue(test, 'id');
      const components = this.testColumnValue({ ...test, componentsCount }, 'components');
      const updated = this.testColumnValue(test, 'updated');
      addOption(options.name, name);
      addOption(options.id, id);
      addOption(options.components, components);
      addOption(options.updated, updated);
    }
    return {
      name: sortOptions(options.name),
      id: sortOptions(options.id),
      components: sortOptions(options.components),
      updated: sortOptions(options.updated)
    };
  });

  readonly revisionSortColumn = signal<RevisionColumnKey>('lastModified');
  readonly revisionSortDir = signal<'asc' | 'desc'>('desc');
  readonly revisionPageIndex = signal(0);
  readonly revisionPageSize = signal(25);
  readonly revisionColumnFilters = signal<{
    revision: string;
    sbomSha: string;
    producer: string;
    tags: string;
    components: string;
    active: string;
    lastModified: string;
  }>({
    revision: '',
    sbomSha: '',
    producer: '',
    tags: '',
    components: '',
    active: '',
    lastModified: ''
  });
  readonly revisionFilterMode = signal<{
    revision: 'contains' | 'select';
    sbomSha: 'contains' | 'select';
    producer: 'contains' | 'select';
    tags: 'contains' | 'select';
    components: 'contains' | 'select';
    active: 'contains' | 'select';
    lastModified: 'contains' | 'select';
  }>({
    revision: 'contains',
    sbomSha: 'contains',
    producer: 'contains',
    tags: 'contains',
    components: 'contains',
    active: 'contains',
    lastModified: 'contains'
  });
  readonly revisionMultiFilters = signal<{
    revision: string[];
    sbomSha: string[];
    producer: string[];
    tags: string[];
    components: string[];
    active: string[];
    lastModified: string[];
  }>({
    revision: [],
    sbomSha: [],
    producer: [],
    tags: [],
    components: [],
    active: [],
    lastModified: []
  });
  readonly revisionFilterVisible = signal<{
    revision: boolean;
    sbomSha: boolean;
    producer: boolean;
    tags: boolean;
    components: boolean;
    active: boolean;
    lastModified: boolean;
  }>({
    revision: false,
    sbomSha: false,
    producer: false,
    tags: false,
    components: false,
    active: false,
    lastModified: false
  });
  readonly revisionFilterPanelOpen = signal(false);
  readonly revisionFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.revisionFilterVisible()) ||
      anyFilterValue(this.revisionColumnFilters())
  );
  readonly revisionFilterOptions = computed(() => {
    const options = {
      revision: new Set<string>(),
      sbomSha: new Set<string>(),
      producer: new Set<string>(),
      tags: new Set<string>(),
      components: new Set<string>(),
      active: new Set<string>(),
      lastModified: new Set<string>()
    };
    for (const revision of this.revisions().slice(0, 500)) {
      addOption(options.revision, this.revisionColumnValue(revision, 'revision'));
      addOption(options.sbomSha, this.revisionColumnValue(revision, 'sbomSha'));
      addOption(options.producer, this.revisionColumnValue(revision, 'producer'));
      addOption(options.tags, this.revisionColumnValue(revision, 'tags'));
      addOption(options.components, this.revisionColumnValue(revision, 'components'));
      addOption(options.active, this.revisionColumnValue(revision, 'active'));
      addOption(options.lastModified, this.revisionColumnValue(revision, 'lastModified'));
    }
    return {
      revision: sortOptions(options.revision),
      sbomSha: sortOptions(options.sbomSha),
      producer: sortOptions(options.producer),
      tags: sortOptions(options.tags),
      components: sortOptions(options.components),
      active: sortOptions(options.active),
      lastModified: sortOptions(options.lastModified)
    };
  });

  readonly selectedRevisionChangeId = signal<string | null>(null);

  readonly lastChangeSortColumn = signal<LastChangeColumnKey>('createdAt');
  readonly lastChangeSortDir = signal<'asc' | 'desc'>('desc');
  readonly lastChangePageIndex = signal(0);
  readonly lastChangePageSize = signal(10);
  readonly lastChangeColumnFilters = signal<{
    toRevision: string;
    fromRevision: string;
    status: string;
    added: string;
    removed: string;
    reappeared: string;
    unchanged: string;
    computedAt: string;
    createdAt: string;
  }>({
    toRevision: '',
    fromRevision: '',
    status: '',
    added: '',
    removed: '',
    reappeared: '',
    unchanged: '',
    computedAt: '',
    createdAt: ''
  });
  readonly lastChangeFilterVisible = signal<{
    toRevision: boolean;
    fromRevision: boolean;
    status: boolean;
    added: boolean;
    removed: boolean;
    reappeared: boolean;
    unchanged: boolean;
    computedAt: boolean;
    createdAt: boolean;
  }>({
    toRevision: false,
    fromRevision: false,
    status: false,
    added: false,
    removed: false,
    reappeared: false,
    unchanged: false,
    computedAt: false,
    createdAt: false
  });
  readonly lastChangeFilterPanelOpen = signal(false);
  readonly lastChangeFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.lastChangeFilterVisible()) ||
      anyFilterValue(this.lastChangeColumnFilters())
  );

  readonly revisionChangeSortColumn = signal<RevisionChangeColumnKey>('createdAt');
  readonly revisionChangeSortDir = signal<'asc' | 'desc'>('desc');
  readonly revisionChangePageIndex = signal(0);
  readonly revisionChangePageSize = signal(25);
  readonly revisionChangeColumnFilters = signal<{
    diffType: string;
    findingType: string;
    componentPurl: string;
    malwarePurl: string;
    createdAt: string;
  }>({
    diffType: '',
    findingType: '',
    componentPurl: '',
    malwarePurl: '',
    createdAt: ''
  });
  readonly revisionChangeFilterVisible = signal<{
    diffType: boolean;
    findingType: boolean;
    componentPurl: boolean;
    malwarePurl: boolean;
    createdAt: boolean;
  }>({
    diffType: false,
    findingType: false,
    componentPurl: false,
    malwarePurl: false,
    createdAt: false
  });
  readonly revisionChangeFilterPanelOpen = signal(false);
  readonly revisionChangeFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.revisionChangeFilterVisible()) ||
      anyFilterValue(this.revisionChangeColumnFilters())
  );

  readonly componentSortColumn = signal<ComponentColumnKey>('purl');
  readonly componentSortDir = signal<'asc' | 'desc'>('asc');
  readonly componentPageIndex = signal(0);
  readonly componentPageSize = signal(componentPreviewLimit);
  readonly componentLoadMode = signal<'preview' | 'all'>('preview');
  readonly componentColumnFilters = signal<{
    purl: string;
    type: string;
    name: string;
    version: string;
    namespace: string;
    licenses: string;
    sbomType: string;
    publisher: string;
    supplier: string;
    malwareVerdict: string;
    malwareScannedAt: string;
    malwareValidUntil: string;
  }>({
    purl: '',
    type: '',
    name: '',
    version: '',
    namespace: '',
    licenses: '',
    sbomType: '',
    publisher: '',
    supplier: '',
    malwareVerdict: '',
    malwareScannedAt: '',
    malwareValidUntil: ''
  });
  readonly componentFilterMode = signal<{
    purl: 'contains' | 'select';
    type: 'contains' | 'select';
    name: 'contains' | 'select';
    version: 'contains' | 'select';
    namespace: 'contains' | 'select';
    licenses: 'contains' | 'select';
    sbomType: 'contains' | 'select';
    publisher: 'contains' | 'select';
    supplier: 'contains' | 'select';
    malwareVerdict: 'contains' | 'select';
    malwareScannedAt: 'contains' | 'select';
    malwareValidUntil: 'contains' | 'select';
  }>({
    purl: 'contains',
    type: 'contains',
    name: 'contains',
    version: 'contains',
    namespace: 'contains',
    licenses: 'contains',
    sbomType: 'contains',
    publisher: 'contains',
    supplier: 'contains',
    malwareVerdict: 'contains',
    malwareScannedAt: 'contains',
    malwareValidUntil: 'contains'
  });
  readonly componentMultiFilters = signal<{
    type: string[];
    namespace: string[];
    licenses: string[];
    sbomType: string[];
    publisher: string[];
    supplier: string[];
  }>({
    type: [],
    namespace: [],
    licenses: [],
    sbomType: [],
    publisher: [],
    supplier: []
  });
  readonly componentFilterPanelOpen = signal(false);
  readonly componentTablePanelOpen = signal(false);
  readonly componentColumnQuery = signal('');
  readonly productTablePanelOpen = signal(false);
  readonly productColumnQuery = signal('');
  readonly productColumnOrder = signal<ProductColumnKey[]>(PRODUCT_COLUMNS.map((column) => column.key));
  readonly productColumnDefinitions = computed(() =>
    orderedColumns(PRODUCT_COLUMNS, this.productColumnOrder())
  );
  readonly availableProductColumns = computed(() =>
    availableColumns(PRODUCT_COLUMNS, this.productColumnOrder(), this.productColumnQuery())
  );

  readonly scopeTablePanelOpen = signal(false);
  readonly scopeColumnQuery = signal('');
  readonly scopeColumnOrder = signal<ScopeColumnKey[]>(SCOPE_COLUMNS.map((column) => column.key));
  readonly scopeColumnDefinitions = computed(() =>
    orderedColumns(SCOPE_COLUMNS, this.scopeColumnOrder())
  );
  readonly availableScopeColumns = computed(() =>
    availableColumns(SCOPE_COLUMNS, this.scopeColumnOrder(), this.scopeColumnQuery())
  );

  readonly testTablePanelOpen = signal(false);
  readonly testColumnQuery = signal('');
  readonly testColumnOrder = signal<TestColumnKey[]>(TEST_COLUMNS.map((column) => column.key));
  readonly testColumnDefinitions = computed(() =>
    orderedColumns(TEST_COLUMNS, this.testColumnOrder())
  );
  readonly availableTestColumns = computed(() =>
    availableColumns(TEST_COLUMNS, this.testColumnOrder(), this.testColumnQuery())
  );

  readonly revisionTablePanelOpen = signal(false);
  readonly revisionColumnQuery = signal('');
  readonly revisionColumnOrder = signal<RevisionColumnKey[]>(REVISION_COLUMNS.map((column) => column.key));
  readonly revisionColumnDefinitions = computed(() =>
    orderedColumns(REVISION_COLUMNS, this.revisionColumnOrder())
  );
  readonly availableRevisionColumns = computed(() =>
    availableColumns(REVISION_COLUMNS, this.revisionColumnOrder(), this.revisionColumnQuery())
  );

  readonly lastChangeTablePanelOpen = signal(false);
  readonly lastChangeColumnQuery = signal('');
  readonly lastChangeColumnOrder = signal<LastChangeColumnKey[]>(LAST_CHANGE_COLUMNS.map((column) => column.key));
  readonly lastChangeColumnDefinitions = computed(() =>
    orderedColumns(LAST_CHANGE_COLUMNS, this.lastChangeColumnOrder())
  );
  readonly availableLastChangeColumns = computed(() =>
    availableColumns(LAST_CHANGE_COLUMNS, this.lastChangeColumnOrder(), this.lastChangeColumnQuery())
  );

  readonly revisionChangeTablePanelOpen = signal(false);
  readonly revisionChangeColumnQuery = signal('');
  readonly revisionChangeColumnOrder = signal<RevisionChangeColumnKey[]>(REVISION_CHANGE_COLUMNS.map((column) => column.key));
  readonly revisionChangeColumnDefinitions = computed(() =>
    orderedColumns(REVISION_CHANGE_COLUMNS, this.revisionChangeColumnOrder())
  );
  readonly availableRevisionChangeColumns = computed(() =>
    availableColumns(REVISION_CHANGE_COLUMNS, this.revisionChangeColumnOrder(), this.revisionChangeColumnQuery())
  );

  readonly componentColumnOrder = signal<ComponentColumnKey[]>(COMPONENT_DEFAULT_COLUMNS);
  readonly componentColumnDefinitions = COMPONENT_COLUMNS;
  readonly availableComponentColumns = computed(() => {
    const query = this.componentColumnQuery().trim().toLowerCase();
    const selected = new Set(this.componentColumnOrder());
    return this.componentColumnDefinitions.filter((def) => {
      if (selected.has(def.key)) {
        return false;
      }
      if (!query) {
        return true;
      }
      return def.label.toLowerCase().includes(query);
    });
  });
  readonly componentFilterVisible = signal<{
    purl: boolean;
    type: boolean;
    name: boolean;
    version: boolean;
    namespace: boolean;
    licenses: boolean;
    sbomType: boolean;
    publisher: boolean;
    supplier: boolean;
    malwareVerdict: boolean;
    malwareScannedAt: boolean;
    malwareValidUntil: boolean;
  }>({
    purl: false,
    type: false,
    name: false,
    version: false,
    namespace: false,
    licenses: false,
    sbomType: false,
    publisher: false,
    supplier: false,
    malwareVerdict: false,
    malwareScannedAt: false,
    malwareValidUntil: false
  });
  readonly componentFilterRowVisible = computed(
    () =>
      anyFilterVisible(this.componentFilterVisible()) ||
      anyFilterValue(this.componentHeaderFilters())
  );
  readonly componentFilterOptions = computed(() => {
    const rows = this.components();
    const options = {
      type: new Set<string>(),
      namespace: new Set<string>(),
      licenses: new Set<string>(),
      sbomType: new Set<string>(),
      publisher: new Set<string>(),
      supplier: new Set<string>()
    };
    for (const row of rows.slice(0, 500)) {
      if (row.pkgType) {
        options.type.add(row.pkgType);
      }
      if (row.pkgNamespace) {
        options.namespace.add(row.pkgNamespace);
      }
      if (row.sbomType) {
        options.sbomType.add(row.sbomType);
      }
      if (row.publisher) {
        options.publisher.add(row.publisher);
      }
      if (row.supplier) {
        options.supplier.add(row.supplier);
      }
      for (const license of extractLicenseValues(row.licenses)) {
        options.licenses.add(license);
      }
    }
    return {
      type: Array.from(options.type).sort(),
      namespace: Array.from(options.namespace).sort(),
      licenses: Array.from(options.licenses).sort(),
      sbomType: Array.from(options.sbomType).sort(),
      publisher: Array.from(options.publisher).sort(),
      supplier: Array.from(options.supplier).sort()
    };
  });
  readonly componentColSpan = computed(() => this.componentColumnOrder().length);

  private readonly componentMalwareResults = signal<Map<string, MalwareResultSummary | null>>(new Map());
  private readonly componentMalwareStatus = signal<Map<string, LoadState>>(new Map());
  private readonly componentMalwareMappings = signal<Map<string, string[]>>(new Map());

  private readonly expandedProducts = signal<ExpandState>(new Set());
  private readonly expandedScopes = signal<ExpandState>(new Set());
  private readonly expandedTests = signal<ExpandState>(new Set());
  private readonly expandedRevisions = signal<ExpandState>(new Set());

  readonly products = computed(() => this.store.products());
  readonly productsStatus = computed(() => this.store.productsLoadState());

  readonly scopes = computed(() => {
    const productId = this.selectedProductId();
    return productId ? this.store.getScopes(productId) : this.store.getAllScopes();
  });

  readonly scopesStatus = computed(() => {
    const productId = this.selectedProductId();
    return productId ? this.store.getScopesStatus(productId) : this.store.getAllScopesStatus();
  });

  readonly tests = computed(() => {
    const scopeId = this.selectedScopeId();
    return scopeId ? this.store.getTests(scopeId) : this.store.getAllTests();
  });

  readonly testsStatus = computed(() => {
    const scopeId = this.selectedScopeId();
    return scopeId ? this.store.getTestsStatus(scopeId) : this.store.getAllTestsStatus();
  });

  readonly selectedTest = computed(() => {
    const testId = this.selectedTestId();
    if (!testId) {
      return null;
    }
    return this.store.findTest(testId);
  });

  readonly revisions = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getRevisions(testId) : [];
  });

  readonly revisionsStatus = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getRevisionsStatus(testId) : 'idle';
  });

  readonly revisionLastChanges = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getRevisionLastChanges(testId) : [];
  });

  readonly revisionLastChangesStatus = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getRevisionLastChangesStatus(testId) : 'idle';
  });

  readonly selectedRevisionChangeSummary = computed(() => {
    const revisionId = this.selectedRevisionChangeId();
    if (!revisionId) {
      return null;
    }
    return this.revisionLastChanges().find((item) => item.toRevisionId === revisionId) ?? null;
  });

  readonly revisionChanges = computed(() => {
    const testId = this.selectedTestId();
    const revisionId = this.selectedRevisionChangeId();
    if (!testId || !revisionId) {
      return [];
    }
    return this.store.getRevisionChanges(testId, revisionId);
  });

  readonly revisionChangesStatus = computed(() => {
    const testId = this.selectedTestId();
    const revisionId = this.selectedRevisionChangeId();
    if (!testId || !revisionId) {
      return 'idle';
    }
    return this.store.getRevisionChangesStatus(testId, revisionId);
  });

  readonly components = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getComponents(testId) : [];
  });

  readonly componentsStatus = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getComponentsStatus(testId) : 'idle';
  });

  readonly componentsLoadedAll = computed(() => {
    const testId = this.selectedTestId();
    return testId ? this.store.getComponentsLoadedAll(testId) : false;
  });

  readonly componentsTotalCount = computed(() => {
    const testId = this.selectedTestId();
    if (!testId) {
      return null;
    }
    return this.store.getComponentsCountFromApi(testId) ?? this.store.getComponentsCount(testId);
  });

  private readonly expandedComponents = signal<Set<string>>(new Set());

  readonly productRows = computed(() => {
    const rows = this.products().map((product) => ({
      ...product,
      scopesCount: this.store.getScopesCount(product.id)
    }));
    return sortRows(
      filterByColumns(
        rows,
        this.productColumnFilters(),
        this.productFilterMode(),
        (row) => ({
          name: row.name ?? '',
          scopes: String(row.scopesCount ?? ''),
          updated: row.updatedAt ?? ''
        }),
        this.productMultiFilters()
      ),
      this.productSortColumn(),
      this.productSortDir(),
      (row, column) => {
        switch (column) {
          case 'name':
            return row.name ?? '';
          case 'scopes':
            return row.scopesCount ?? -1;
          case 'updated':
            return row.updatedAt ?? '';
        }
      }
    );
  });

  readonly productTotal = computed(() => this.productRows().length);
  readonly productPage = computed(() =>
    paginate(this.productRows(), this.productPageIndex(), this.productPageSize())
  );
  readonly productTotalPages = computed(() =>
    this.totalPages(this.productTotal(), this.productPageSize())
  );

  readonly scopeRows = computed(() => {
    const rows = this.scopes().map((scope) => ({
      ...scope,
      testsCount: this.store.getTestsCount(scope.id)
    }));
    return sortRows(
      filterByColumns(
        rows,
        this.scopeColumnFilters(),
        this.scopeFilterMode(),
        (row) => ({
          name: row.name ?? '',
          tests: String(row.testsCount ?? ''),
          updated: row.updatedAt ?? ''
        }),
        this.scopeMultiFilters()
      ),
      this.scopeSortColumn(),
      this.scopeSortDir(),
      (row, column) => {
        switch (column) {
          case 'name':
            return row.name ?? '';
          case 'tests':
            return row.testsCount ?? -1;
          case 'updated':
            return row.updatedAt ?? '';
        }
      }
    );
  });

  readonly scopeTotal = computed(() => this.scopeRows().length);
  readonly scopePage = computed(() =>
    paginate(this.scopeRows(), this.scopePageIndex(), this.scopePageSize())
  );
  readonly scopeTotalPages = computed(() => this.totalPages(this.scopeTotal(), this.scopePageSize()));

  readonly testRows = computed(() => {
    const rows = this.tests().map((test) => ({
      ...test,
      componentsCount: this.store.getComponentsCount(test.id)
    }));
    return sortRows(
      filterByColumns(
        rows,
        this.testColumnFilters(),
        this.testFilterMode(),
        (row) => ({
          name: row.name ?? '',
          id: row.id ?? '',
          components: String(row.componentsCount ?? ''),
          updated: row.updatedAt ?? ''
        }),
        this.testMultiFilters()
      ),
      this.testSortColumn(),
      this.testSortDir(),
      (row, column) => {
        switch (column) {
          case 'name':
            return row.name ?? '';
          case 'id':
            return row.id ?? '';
          case 'components':
            return row.componentsCount ?? -1;
          case 'updated':
            return row.updatedAt ?? '';
        }
      }
    );
  });

  readonly testTotal = computed(() => this.testRows().length);
  readonly testPage = computed(() =>
    paginate(this.testRows(), this.testPageIndex(), this.testPageSize())
  );
  readonly testTotalPages = computed(() => this.totalPages(this.testTotal(), this.testPageSize()));

  readonly revisionRows = computed(() => {
    const rows = this.revisions();
    return sortRows(
      filterByColumns(
        rows,
        this.revisionColumnFilters(),
        this.revisionFilterMode(),
        (row) => ({
          revision: row.id ?? '',
          sbomSha: row.sbomSha256 ?? '',
          producer: row.sbomProducer ?? '',
          tags: (row.tags ?? []).join(','),
          components: String(row.componentsImportedCount ?? ''),
          active: row.isActive ? 'yes' : 'no',
          lastModified: row.lastModifiedAt ?? row.createdAt ?? ''
        }),
        this.revisionMultiFilters()
      ),
      this.revisionSortColumn(),
      this.revisionSortDir(),
      (row, column) => {
        switch (column) {
          case 'revision':
            return row.id ?? '';
          case 'sbomSha':
            return row.sbomSha256 ?? '';
          case 'producer':
            return row.sbomProducer ?? '';
          case 'tags':
            return (row.tags ?? []).join(',');
          case 'components':
            return row.componentsImportedCount ?? -1;
          case 'active':
            return row.isActive ? 1 : 0;
          case 'lastModified':
            return row.lastModifiedAt ?? row.createdAt ?? '';
        }
      }
    );
  });

  readonly revisionTotal = computed(() => this.revisionRows().length);
  readonly revisionPage = computed(() =>
    paginate(this.revisionRows(), this.revisionPageIndex(), this.revisionPageSize())
  );
  readonly revisionTotalPages = computed(() =>
    this.totalPages(this.revisionTotal(), this.revisionPageSize())
  );

  readonly lastChangeRows = computed(() => {
    const rows = this.revisionLastChanges();
    return sortRows(
      filterByColumns(
        rows,
        this.lastChangeColumnFilters(),
        {
          toRevision: 'contains',
          fromRevision: 'contains',
          status: 'contains',
          added: 'contains',
          removed: 'contains',
          reappeared: 'contains',
          unchanged: 'contains',
          computedAt: 'contains',
          createdAt: 'contains'
        },
        (row) => ({
          toRevision: row.toRevisionId ?? '',
          fromRevision: row.fromRevisionId ?? '',
          status: row.status ?? '',
          added: String(row.addedCount ?? 0),
          removed: String(row.removedCount ?? 0),
          reappeared: String(row.reappearedCount ?? 0),
          unchanged: String(row.unchangedCount ?? 0),
          computedAt: row.computedAt ?? '',
          createdAt: row.createdAt ?? ''
        })
      ),
      this.lastChangeSortColumn(),
      this.lastChangeSortDir(),
      (row, column) => {
        switch (column) {
          case 'toRevision':
            return row.toRevisionId ?? '';
          case 'fromRevision':
            return row.fromRevisionId ?? '';
          case 'status':
            return row.status ?? '';
          case 'added':
            return row.addedCount ?? -1;
          case 'removed':
            return row.removedCount ?? -1;
          case 'reappeared':
            return row.reappearedCount ?? -1;
          case 'unchanged':
            return row.unchangedCount ?? -1;
          case 'computedAt':
            return row.computedAt ?? '';
          case 'createdAt':
            return row.createdAt ?? '';
        }
      }
    );
  });

  readonly lastChangeTotal = computed(() => this.lastChangeRows().length);
  readonly lastChangePage = computed(() =>
    paginate(this.lastChangeRows(), this.lastChangePageIndex(), this.lastChangePageSize())
  );
  readonly lastChangeTotalPages = computed(() =>
    this.totalPages(this.lastChangeTotal(), this.lastChangePageSize())
  );
  readonly hasRevisionChangeInProgress = computed(() =>
    this.revisionLastChanges().some((row) => {
      const status = (row.status ?? '').toUpperCase();
      return status === 'PENDING' || status === 'PROCESSING';
    })
  );

  readonly revisionChangeRows = computed(() => {
    const rows = this.revisionChanges();
    return sortRows(
      filterByColumns(
        rows,
        this.revisionChangeColumnFilters(),
        {
          diffType: 'contains',
          findingType: 'contains',
          componentPurl: 'contains',
          malwarePurl: 'contains',
          createdAt: 'contains'
        },
        (row) => ({
          diffType: row.diffType ?? '',
          findingType: row.findingType ?? '',
          componentPurl: row.componentPurl ?? '',
          malwarePurl: row.malwarePurl ?? '',
          createdAt: row.createdAt ?? ''
        })
      ),
      this.revisionChangeSortColumn(),
      this.revisionChangeSortDir(),
      (row, column) => {
        switch (column) {
          case 'diffType':
            return row.diffType ?? '';
          case 'findingType':
            return row.findingType ?? '';
          case 'componentPurl':
            return row.componentPurl ?? '';
          case 'malwarePurl':
            return row.malwarePurl ?? '';
          case 'createdAt':
            return row.createdAt ?? '';
        }
      }
    );
  });

  readonly revisionChangeTotal = computed(() => this.revisionChangeRows().length);
  readonly revisionChangePage = computed(() =>
    paginate(this.revisionChangeRows(), this.revisionChangePageIndex(), this.revisionChangePageSize())
  );
  readonly revisionChangeTotalPages = computed(() =>
    this.totalPages(this.revisionChangeTotal(), this.revisionChangePageSize())
  );

  readonly componentRows = computed(() => {
    const rows = this.components();
    return sortRows(
      this.filterComponents(rows),
      this.componentSortColumn(),
      this.componentSortDir(),
      (row, column) => {
        switch (column) {
          case 'purl':
            return row.purl ?? '';
          case 'pkgType':
            return row.pkgType ?? '';
          case 'pkgName':
            return row.pkgName ?? '';
          case 'version':
            return row.version ?? '';
          case 'pkgNamespace':
            return row.pkgNamespace ?? '';
          case 'licenses':
            return this.formatLicensesDetail(row.licenses);
          case 'sbomType':
            return row.sbomType ?? '';
          case 'publisher':
            return row.publisher ?? '';
          case 'supplier':
            return row.supplier ?? '';
          case 'malwareVerdict':
            return this.getComponentMalwareResult(row.purl ?? '')?.verdict ?? '';
          case 'malwareScannedAt':
            return this.getComponentMalwareResult(row.purl ?? '')?.scannedAt ?? '';
          case 'malwareValidUntil':
            return this.getComponentMalwareResult(row.purl ?? '')?.validUntil ?? '';
        }
      }
    );
  });

  readonly componentTotal = computed(() => this.componentRows().length);
  readonly componentPage = computed(() =>
    paginate(this.componentRows(), this.componentPageIndex(), this.componentPageSize())
  );
  readonly componentTotalPages = computed(() =>
    this.componentsLoadedAll() ? this.totalPages(this.componentTotal(), this.componentPageSize()) : 1
  );

  readonly pageSizeOptions = [10, 25, 50, 100, 0];

  constructor() {
    this.destroyRef.onDestroy(() => this.stopRevisionChangesPolling());

    this.route.queryParamMap
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe((params) => this.applyQueryParams(params));

    effect(() => {
      this.store.ensureProducts();
    });

    effect(() => {
      const section = this.section();
      const productId = this.selectedProductId();
      const scopeId = this.selectedScopeId();

      if (section === 'products') {
        this.store.ensureAllScopes();
        this.store.ensureAllTests();
      }

      if (section === 'scopes' && productId) {
        this.store.ensureScopes(productId);
        // Scope table shows total tests per scope, which is derived from the full test list.
        this.store.ensureAllTests();
      }

      if (section === 'scopes' && !productId) {
        this.store.ensureAllScopes();
        this.store.ensureAllTests();
      }

      if (section === 'tests' && scopeId) {
        if (productId) {
          this.store.ensureScopes(productId);
        } else {
          this.store.ensureAllScopes();
        }
        this.store.ensureTests(scopeId);
      }

      if (section === 'tests' && !scopeId) {
        this.store.ensureAllTests();
        this.store.ensureAllScopes();
      }
    });

    effect(() => {
      if (this.section() !== 'tests' || this.isTestDetail()) {
        return;
      }
      if (this.testsStatus() !== 'loaded') {
        return;
      }

      const visibleTests = this.testPage();
      for (const test of visibleTests) {
        const status = this.store.getComponentsCountStatus(test.id);
        if (status === 'idle' || status === 'error') {
          void this.store.ensureComponentsCount(test.id);
        }
      }
    });

    effect(() => {
      if (!this.isTestDetail()) {
        return;
      }
      const testId = this.selectedTestId();
      if (!testId) {
        return;
      }
      this.store.ensureAllTests();
      this.store.ensureAllScopes();

      const test = this.store.findTest(testId);
      const resolvedScopeId = this.selectedScopeId() ?? test?.scopeId ?? null;
      if (resolvedScopeId && this.selectedScopeId() !== resolvedScopeId) {
        this.selectedScopeId.set(resolvedScopeId);
      }
      if (!resolvedScopeId) {
        return;
      }

      this.store.ensureTests(resolvedScopeId);
      const scope = this.store.findScope(resolvedScopeId);
      const resolvedProductId = this.selectedProductId() ?? scope?.productId ?? null;
      if (resolvedProductId && this.selectedProductId() !== resolvedProductId) {
        this.selectedProductId.set(resolvedProductId);
      }
    });

    effect(() => {
      const isDetail = this.isTestDetail();
      const testId = this.selectedTestId();
      const componentQ = this.componentQ().trim();

      if (!isDetail || !testId) {
        return;
      }

      if (testId != this.lastComponentsTestId) {
        this.lastComponentsTestId = testId;
        const hasAll = this.store.getComponentsLoadedAll(testId);
        this.componentLoadMode.set(hasAll ? 'all' : 'preview');
        this.componentPageIndex.set(0);
        this.componentPageSize.set(hasAll ? 10 : componentPreviewLimit);
      }

      const revisionsStatus = this.store.getRevisionsStatus(testId);
      if (revisionsStatus === 'idle' || revisionsStatus === 'error') {
        this.store.ensureRevisions(testId);
      }

      const componentsCountStatus = this.store.getComponentsCountStatus(testId);
      if (componentsCountStatus === 'idle' || componentsCountStatus === 'error') {
        this.store.ensureComponentsCount(testId);
      }

      if (componentQ.length > 0) {
        const last = this.lastComponentQByTest.get(testId) ?? '';
        if (last !== componentQ) {
          this.lastComponentQByTest.set(testId, componentQ);
          // Switch to "all" behaviour for a stable table UX (filters/pagination) on a small, narrowed dataset.
          this.componentLoadMode.set('all');
          this.componentPageIndex.set(0);
          this.componentPageSize.set(10);
          this.componentFilterPanelOpen.set(false);
          this.componentTablePanelOpen.set(false);
          this.expandedComponents.set(new Set());
          void this.store.reloadComponentsByQuery(testId, componentQ, 200);
        }
        return;
      }

      const componentsStatus = this.store.getComponentsStatus(testId);
      if (
        this.componentLoadMode() === 'preview' &&
        !this.store.getComponentsLoadedAll(testId) &&
        (componentsStatus === 'idle' || componentsStatus === 'error')
      ) {
        this.store.ensureComponentsPreview(testId, componentPreviewLimit);
      }
    });

    effect(() => {
      if (!this.isTestDetail()) {
        return;
      }
      void this.components();
      void this.componentColumnFilters();
    });

    effect(() => {
      if (!this.isTestDetail()) {
        return;
      }
      const components = this.componentsLoadedAll() ? this.components() : this.componentPage();
      for (const component of components) {
        const purl = component.purl ?? '';
        if (!purl) {
          continue;
        }
        if (this.getComponentMalwareStatus(purl) === 'idle') {
          void this.ensureComponentMalwareResult(purl);
        }
      }
    });

    effect(() => {
      const isDetail = this.isTestDetail();
      const testId = this.selectedTestId();
      if (!isDetail || !testId) {
        this.stopRevisionChangesPolling();
        return;
      }
      this.store.ensureRevisionLastChanges(testId);
    });

    effect(() => {
      const isDetail = this.isTestDetail();
      const testId = this.selectedTestId();
      if (!isDetail || !testId) {
        this.stopRevisionChangesPolling();
        return;
      }
      const shouldPoll = this.hasRevisionChangeInProgress();
      if (shouldPoll) {
        this.startRevisionChangesPolling(testId);
      } else {
        this.stopRevisionChangesPolling();
      }
    });

    effect(() => {
      if (!this.isTestDetail()) {
        this.selectedRevisionChangeId.set(null);
        return;
      }
      const rows = this.revisionLastChanges();
      if (rows.length === 0) {
        this.selectedRevisionChangeId.set(null);
        return;
      }
      const selected = this.selectedRevisionChangeId();
      if (selected && rows.some((row) => row.toRevisionId === selected)) {
        return;
      }
      this.selectedRevisionChangeId.set(null);
    });

    effect(() => {
      if (!this.isTestDetail()) {
        return;
      }
      const testId = this.selectedTestId();
      const revisionId = this.selectedRevisionChangeId();
      if (!testId || !revisionId) {
        return;
      }
      this.store.ensureRevisionChangesSummary(testId, revisionId);
    });

    effect(() => {
      if (!this.isTestDetail()) {
        return;
      }
      const testId = this.selectedTestId();
      const revisionId = this.selectedRevisionChangeId();
      const selectedRow = this.selectedRevisionChangeSummary();
      if (!testId || !revisionId || !selectedRow) {
        return;
      }
      const summaryStatus = (selectedRow.status ?? '').toUpperCase();
      if (summaryStatus === 'COMPLETED' || summaryStatus === 'FAILED') {
        this.store.ensureRevisionChanges(testId, revisionId);
      }
    });

    effect(() => {
      if (this.isSyncingFromUrl) {
        return;
      }
      const params = this.buildQueryParams();
      const encoded = JSON.stringify(params);
      if (encoded === this.lastSyncedParams) {
        return;
      }
      this.lastSyncedParams = encoded;
      void this.router.navigate([], {
        relativeTo: this.route,
        queryParams: params,
        replaceUrl: true
      });
    });

    effect(() => this.resetPageOnFilterChangeSignal(this.productColumnFilters, this.productPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.productFilterMode, this.productPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.productMultiFilters, this.productPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.scopeColumnFilters, this.scopePageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.scopeFilterMode, this.scopePageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.scopeMultiFilters, this.scopePageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.testColumnFilters, this.testPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.testFilterMode, this.testPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.testMultiFilters, this.testPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.revisionColumnFilters, this.revisionPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.revisionFilterMode, this.revisionPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.revisionMultiFilters, this.revisionPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.lastChangeColumnFilters, this.lastChangePageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.revisionChangeColumnFilters, this.revisionChangePageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.componentColumnFilters, this.componentPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.componentMultiFilters, this.componentPageIndex));
    effect(() => this.resetPageOnFilterChangeSignal(this.componentFilterMode, this.componentPageIndex));

    effect(() => this.clampPage(this.productPageIndex, this.productTotal, this.productPageSize));
    effect(() => this.clampPage(this.scopePageIndex, this.scopeTotal, this.scopePageSize));
    effect(() => this.clampPage(this.testPageIndex, this.testTotal, this.testPageSize));
    effect(() => this.clampPage(this.revisionPageIndex, this.revisionTotal, this.revisionPageSize));
    effect(() => this.clampPage(this.lastChangePageIndex, this.lastChangeTotal, this.lastChangePageSize));
    effect(() => this.clampPage(this.revisionChangePageIndex, this.revisionChangeTotal, this.revisionChangePageSize));
    effect(() => this.clampPage(this.componentPageIndex, this.componentTotal, this.componentPageSize));
  }

  setSection(section: DataSection): void {
    this.stopRevisionChangesPolling();
    this.section.set(section);
    this.isTestDetail.set(false);
    this.selectedProductId.set(null);
    this.selectedScopeId.set(null);
    this.selectedTestId.set(null);
    this.selectedRevisionChangeId.set(null);
    this.expandedProducts.set(new Set());
    this.expandedScopes.set(new Set());
    this.expandedTests.set(new Set());
    this.expandedComponents.set(new Set());
    this.expandedRevisions.set(new Set());
  }

  selectProduct(product: ProductSummary): void {
    this.selectedProductId.set(product.id);
    this.selectedScopeId.set(null);
    this.selectedTestId.set(null);
    this.section.set('scopes');
    this.isTestDetail.set(false);
    this.store.ensureScopes(product.id);
  }

  selectScope(scope: ScopeSummary): void {
    if (!this.selectedProductId() && scope.productId) {
      this.selectedProductId.set(scope.productId);
    }
    this.selectedScopeId.set(scope.id);
    this.selectedTestId.set(null);
    this.section.set('tests');
    this.isTestDetail.set(false);
    this.store.ensureTests(scope.id);
  }

  openTestDetail(test: TestSummary): void {
    if (!this.selectedScopeId() && test.scopeId) {
      this.selectedScopeId.set(test.scopeId);
      const scope = this.store.findScope(test.scopeId);
      if (scope?.productId) {
        this.selectedProductId.set(scope.productId);
      }
    }
    this.selectedTestId.set(test.id);
    this.isTestDetail.set(true);
    this.selectedRevisionChangeId.set(null);
    this.revisionChangePageIndex.set(0);
    this.expandedComponents.set(new Set());
    this.expandedRevisions.set(new Set());
  }

  backToTests(): void {
    this.stopRevisionChangesPolling();
    this.isTestDetail.set(false);
    this.selectedRevisionChangeId.set(null);
    this.expandedComponents.set(new Set());
    this.expandedRevisions.set(new Set());
  }

  backToProducts(): void {
    this.section.set('products');
    this.selectedProductId.set(null);
    this.selectedScopeId.set(null);
    this.selectedTestId.set(null);
    this.expandedScopes.set(new Set());
  }

  backToScopes(): void {
    const productId = this.selectedProductId();
    if (productId) {
      this.section.set('scopes');
      this.selectedScopeId.set(null);
      this.selectedTestId.set(null);
      this.expandedTests.set(new Set());
      this.store.ensureScopes(productId);
    } else {
      // Fallback if somehow no product is selected (should not happen in normal flow)
      this.backToProducts();
    }
  }

  navigateToProduct(): void {
    const productId = this.selectedProductId();
    if (!productId) {
      return;
    }
    this.section.set('scopes');
    this.isTestDetail.set(false);
    this.selectedScopeId.set(null);
    this.selectedTestId.set(null);
    this.store.ensureScopes(productId);
  }

  navigateToScope(): void {
    const scopeId = this.selectedScopeId();
    if (!scopeId) {
      return;
    }
    this.section.set('tests');
    this.isTestDetail.set(false);
    this.selectedTestId.set(null);
    this.store.ensureTests(scopeId);
  }

  navigateToTest(): void {
    const testId = this.selectedTestId();
    if (!testId) {
      return;
    }
    this.section.set('tests');
    this.isTestDetail.set(true);
  }

  getProductName(productId: string | null | undefined): string {
    if (!productId) {
      return 'All Products';
    }
    return this.store.findProduct(productId)?.name ?? productId;
  }

  getScopeName(scopeId: string | null | undefined): string {
    if (!scopeId) {
      return 'All Scopes';
    }
    return this.store.findScope(scopeId)?.name ?? scopeId;
  }

  getTestName(testId: string | null | undefined): string {
    if (!testId) {
      return 'All Tests';
    }
    return this.store.findTest(testId)?.name ?? testId;
  }

  toggleExpanded(itemId: string): void {
    const section = this.section();
    const state = this.getExpandedState(section);
    const next = new Set(state);

    if (next.has(itemId)) {
      next.delete(itemId);
    } else {
      next.add(itemId);
    }

    this.setExpandedState(section, next);
  }

  isExpanded(itemId: string): boolean {
    const section = this.section();
    const state = this.getExpandedState(section);
    return state.has(itemId);
  }

  productExpandedIds(): ReadonlySet<string> {
    return this.expandedProducts();
  }

  scopeExpandedIds(): ReadonlySet<string> {
    return this.expandedScopes();
  }

  testExpandedIds(): ReadonlySet<string> {
    return this.expandedTests();
  }

  onRowClick(itemId: string): void {
    this.toggleExpanded(itemId);
  }

  onArrowClick(event: MouseEvent, item: SectionItem): void {
    event.stopPropagation();

    if (this.section() === 'products') {
      this.selectProduct(item as ProductSummary);
      return;
    }

    if (this.section() === 'scopes') {
      this.selectScope(item as ScopeSummary);
      return;
    }

    this.openTestDetail(item as TestSummary);
  }

  stopEvent(event: Event): void {
    event.stopPropagation();
  }

  openProductJiraSettings(product: ProductSummary): void {
    this.openJiraSettingsDialog('PRODUCT', product.id, product.name ?? product.id);
  }

  openScopeJiraSettings(scope: ScopeSummary): void {
    this.openJiraSettingsDialog('SCOPE', scope.id, scope.name ?? scope.id);
  }

  openTestJiraSettings(test: TestSummary): void {
    this.openJiraSettingsDialog('TEST', test.id, test.name ?? test.id);
  }

  async createProduct(): Promise<void> {
    if (!this.canWrite()) {
      return;
    }

    const ref = this.dialog.open(NamePromptDialogComponent, {
      width: '520px',
      data: {
        title: 'Create product',
        label: 'Product name',
        confirmLabel: 'Create'
      }
    });

    const name = (await firstValueFrom(ref.afterClosed())) ?? null;
    if (!name) {
      return;
    }

    await this.runMutation(async () => {
      await this.api.createProduct(name);
      await this.store.reloadProducts();
    }, `✓ Product created: ${name}`);
  }

  async createScope(): Promise<void> {
    if (!this.canWrite()) {
      return;
    }

    const productId = this.selectedProductId();
    if (!productId) {
      this.snackBar.open('Select a product first to add a scope.', 'Dismiss', { duration: 3000 });
      return;
    }

    const ref = this.dialog.open(NamePromptDialogComponent, {
      width: '520px',
      data: {
        title: 'Create scope',
        label: 'Scope name',
        confirmLabel: 'Create'
      }
    });

    const name = (await firstValueFrom(ref.afterClosed())) ?? null;
    if (!name) {
      return;
    }

    await this.runMutation(async () => {
      await this.api.createScope(productId, name);
      await this.store.reloadScopes(productId);
      await this.store.reloadAllScopes();
    }, `✓ Scope created: ${name}`);
  }

  importSbomToSelectedScope(): void {
    if (!this.canWrite()) {
      return;
    }

    const productId = this.selectedProductId();
    const scopeId = this.selectedScopeId();
    if (!productId || !scopeId) {
      this.snackBar.open('Select a product and scope first to import SBOMs.', 'Dismiss', { duration: 3000 });
      return;
    }

    void this.router.navigate(['/data/import'], {
      queryParams: { productId, scopeId }
    });
  }

  async deleteProduct(product: ProductSummary): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }
    const confirmed = await this.confirmDelete(`product '${product.name}'`);
    if (!confirmed) {
      return;
    }

    await this.runMutation(async () => {
      await this.api.deleteProduct(product.id);
      await this.store.reloadProducts();
      await this.store.reloadAllScopes();
      await this.store.reloadAllTests();
    }, `✓ Product deleted: ${product.name}`);
  }

  async deleteScope(scope: ScopeSummary): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }

    const confirmed = await this.confirmDelete(`scope '${scope.name}'`);
    if (!confirmed) {
      return;
    }

    await this.runMutation(async () => {
      await this.api.deleteScope(scope.id);
      const productId = this.selectedProductId();
      if (productId) {
        await this.store.reloadScopes(productId);
      } else if (scope.productId) {
        await this.store.reloadScopes(scope.productId);
      }
      await this.store.reloadAllScopes();
      await this.store.reloadAllTests();
    }, `✓ Scope deleted: ${scope.name}`);
  }

  async deleteTest(test: TestSummary): Promise<void> {
    if (!this.isAdmin()) {
      return;
    }

    const confirmed = await this.confirmDelete(`test '${test.name}'`);
    if (!confirmed) {
      return;
    }

    await this.runMutation(async () => {
      await this.api.deleteTest(test.id);
      if (this.selectedTestId() === test.id) {
        this.backToTests();
      }
      const scopeId = this.selectedScopeId() ?? test.scopeId;
      if (scopeId) {
        await this.store.reloadTests(scopeId);
      }
      await this.store.reloadAllTests();
    }, `✓ Test deleted: ${test.name}`);
  }

  private async confirmDelete(target: string): Promise<boolean> {
    const ref = this.dialog.open(ConfirmDialogComponent, {
      width: '520px',
      data: {
        title: 'Confirm delete',
        message: `Are you sure you want to delete ${target}? This cannot be undone.`
      }
    });
    return (await firstValueFrom(ref.afterClosed())) === true;
  }

  private openJiraSettingsDialog(level: 'PRODUCT' | 'SCOPE' | 'TEST', targetId: string, targetName: string): void {
    if (!targetId) {
      return;
    }
    this.dialog.open(JiraEntitySettingsDialogComponent, {
      width: '1120px',
      maxWidth: '96vw',
      data: {
        level,
        targetId,
        targetName,
      },
    });
  }

  private async runMutation(action: () => Promise<void>, _successMessage: string): Promise<void> {
    void _successMessage;
    if (this.isMutating()) {
      return;
    }
    this.isMutating.set(true);
    try {
      await action();
    } catch (error) {
      const message = this.resolveMutationErrorMessage(error);
      this.snackBar.open(message, 'Dismiss', { duration: 4500 });
      throw error;
    } finally {
      this.isMutating.set(false);
    }
  }

  private resolveMutationErrorMessage(error: unknown): string {
    if (error instanceof HttpErrorResponse) {
      if (error.status === 403) {
        return 'You do not have permission to perform this action.';
      }
      if (error.status === 404) {
        return 'Item not found.';
      }
    }
    return 'Action failed. Please try again.';
  }

  toggleProductFilter(column: ProductColumnKey, event?: MouseEvent): void {
    event?.stopPropagation();
    this.productFilterVisible.set(toggleVisibility(this.productFilterVisible(), column));
  }

  toggleProductFilterPanel(): void {
    const next = !this.productFilterPanelOpen();
    this.productFilterPanelOpen.set(next);
  }

  toggleScopeFilter(column: ScopeColumnKey, event?: MouseEvent): void {
    event?.stopPropagation();
    this.scopeFilterVisible.set(toggleVisibility(this.scopeFilterVisible(), column));
  }

  toggleScopeFilterPanel(): void {
    const next = !this.scopeFilterPanelOpen();
    this.scopeFilterPanelOpen.set(next);
  }

  toggleTestFilter(column: TestColumnKey, event?: MouseEvent): void {
    event?.stopPropagation();
    this.testFilterVisible.set(toggleVisibility(this.testFilterVisible(), column));
  }

  toggleTestFilterPanel(): void {
    const next = !this.testFilterPanelOpen();
    this.testFilterPanelOpen.set(next);
  }

  toggleRevisionFilter(
    column: RevisionColumnKey,
    event?: MouseEvent
  ): void {
    event?.stopPropagation();
    this.revisionFilterVisible.set(toggleVisibility(this.revisionFilterVisible(), column));
  }

  toggleRevisionFilterPanel(): void {
    const next = !this.revisionFilterPanelOpen();
    this.revisionFilterPanelOpen.set(next);
  }

  toggleLastChangeFilter(column: LastChangeColumnKey, event?: MouseEvent): void {
    event?.stopPropagation();
    this.lastChangeFilterVisible.set(toggleVisibility(this.lastChangeFilterVisible(), column));
  }

  toggleLastChangeFilterPanel(): void {
    const next = !this.lastChangeFilterPanelOpen();
    this.lastChangeFilterPanelOpen.set(next);
    this.lastChangeFilterVisible.set(
      next
        ? enableAllVisibility(this.lastChangeFilterVisible())
        : visibilityFromValues(this.lastChangeColumnFilters())
    );
  }

  toggleRevisionChangeFilter(column: RevisionChangeColumnKey, event?: MouseEvent): void {
    event?.stopPropagation();
    this.revisionChangeFilterVisible.set(toggleVisibility(this.revisionChangeFilterVisible(), column));
  }

  toggleRevisionChangeFilterPanel(): void {
    const next = !this.revisionChangeFilterPanelOpen();
    this.revisionChangeFilterPanelOpen.set(next);
    this.revisionChangeFilterVisible.set(
      next
        ? enableAllVisibility(this.revisionChangeFilterVisible())
        : visibilityFromValues(this.revisionChangeColumnFilters())
    );
  }

  toggleProductTablePanel(): void {
    const next = !this.productTablePanelOpen();
    this.productTablePanelOpen.set(next);
  }

  toggleScopeTablePanel(): void {
    const next = !this.scopeTablePanelOpen();
    this.scopeTablePanelOpen.set(next);
  }

  toggleTestTablePanel(): void {
    const next = !this.testTablePanelOpen();
    this.testTablePanelOpen.set(next);
  }

  toggleRevisionTablePanel(): void {
    const next = !this.revisionTablePanelOpen();
    this.revisionTablePanelOpen.set(next);
  }

  toggleLastChangeTablePanel(): void {
    const next = !this.lastChangeTablePanelOpen();
    this.lastChangeTablePanelOpen.set(next);
  }

  toggleRevisionChangeTablePanel(): void {
    const next = !this.revisionChangeTablePanelOpen();
    this.revisionChangeTablePanelOpen.set(next);
  }

  setProductColumnQuery(event: Event): void {
    this.productColumnQuery.set(readInputValue(event));
  }

  setScopeColumnQuery(event: Event): void {
    this.scopeColumnQuery.set(readInputValue(event));
  }

  setTestColumnQuery(event: Event): void {
    this.testColumnQuery.set(readInputValue(event));
  }

  setRevisionColumnQuery(event: Event): void {
    this.revisionColumnQuery.set(readInputValue(event));
  }

  setLastChangeColumnQuery(event: Event): void {
    this.lastChangeColumnQuery.set(readInputValue(event));
  }

  setRevisionChangeColumnQuery(event: Event): void {
    this.revisionChangeColumnQuery.set(readInputValue(event));
  }

  addProductColumn(column: ProductColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.productColumnOrder();
    if (current.includes(column)) {
      this.productColumnQuery.set('');
      return;
    }
    this.productColumnOrder.set([...current, column]);
    this.productColumnQuery.set('');
  }

  addScopeColumn(column: ScopeColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.scopeColumnOrder();
    if (current.includes(column)) {
      this.scopeColumnQuery.set('');
      return;
    }
    this.scopeColumnOrder.set([...current, column]);
    this.scopeColumnQuery.set('');
  }

  addTestColumn(column: TestColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.testColumnOrder();
    if (current.includes(column)) {
      this.testColumnQuery.set('');
      return;
    }
    this.testColumnOrder.set([...current, column]);
    this.testColumnQuery.set('');
  }

  addRevisionColumn(column: RevisionColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.revisionColumnOrder();
    if (current.includes(column)) {
      this.revisionColumnQuery.set('');
      return;
    }
    this.revisionColumnOrder.set([...current, column]);
    this.revisionColumnQuery.set('');
  }

  addLastChangeColumn(column: LastChangeColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.lastChangeColumnOrder();
    if (current.includes(column)) {
      this.lastChangeColumnQuery.set('');
      return;
    }
    this.lastChangeColumnOrder.set([...current, column]);
    this.lastChangeColumnQuery.set('');
  }

  addRevisionChangeColumn(column: RevisionChangeColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.revisionChangeColumnOrder();
    if (current.includes(column)) {
      this.revisionChangeColumnQuery.set('');
      return;
    }
    this.revisionChangeColumnOrder.set([...current, column]);
    this.revisionChangeColumnQuery.set('');
  }

  removeProductColumn(column: ProductColumnKey): void {
    if (column === 'name') {
      return;
    }
    const next = this.productColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.productColumnOrder.set(next);
  }

  removeScopeColumn(column: ScopeColumnKey): void {
    if (column === 'name') {
      return;
    }
    const next = this.scopeColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.scopeColumnOrder.set(next);
  }

  removeTestColumn(column: TestColumnKey): void {
    if (column === 'name') {
      return;
    }
    const next = this.testColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.testColumnOrder.set(next);
  }

  removeRevisionColumn(column: RevisionColumnKey): void {
    if (column === 'revision') {
      return;
    }
    const next = this.revisionColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.revisionColumnOrder.set(next);
  }

  removeLastChangeColumn(column: LastChangeColumnKey): void {
    if (column === 'toRevision') {
      return;
    }
    const next = this.lastChangeColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.lastChangeColumnOrder.set(next);
  }

  removeRevisionChangeColumn(column: RevisionChangeColumnKey): void {
    if (column === 'diffType') {
      return;
    }
    const next = this.revisionChangeColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.revisionChangeColumnOrder.set(next);
  }

  dropProductColumn(event: CdkDragDrop<ProductColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.productColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.productColumnOrder.set(next);
  }

  dropScopeColumn(event: CdkDragDrop<ScopeColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.scopeColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.scopeColumnOrder.set(next);
  }

  dropTestColumn(event: CdkDragDrop<TestColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.testColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.testColumnOrder.set(next);
  }

  dropRevisionColumn(event: CdkDragDrop<RevisionColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.revisionColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.revisionColumnOrder.set(next);
  }

  dropLastChangeColumn(event: CdkDragDrop<LastChangeColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.lastChangeColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.lastChangeColumnOrder.set(next);
  }

  dropRevisionChangeColumn(event: CdkDragDrop<RevisionChangeColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.revisionChangeColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.revisionChangeColumnOrder.set(next);
  }

  productColumnLabel(column: ProductColumnKey): string {
    return columnLabel(PRODUCT_COLUMNS, column);
  }

  scopeColumnLabel(column: ScopeColumnKey): string {
    return columnLabel(SCOPE_COLUMNS, column);
  }

  testColumnLabel(column: TestColumnKey): string {
    return columnLabel(TEST_COLUMNS, column);
  }

  revisionColumnLabel(column: RevisionColumnKey): string {
    return columnLabel(REVISION_COLUMNS, column);
  }

  lastChangeColumnLabel(column: LastChangeColumnKey): string {
    return columnLabel(LAST_CHANGE_COLUMNS, column);
  }

  revisionChangeColumnLabel(column: RevisionChangeColumnKey): string {
    return columnLabel(REVISION_CHANGE_COLUMNS, column);
  }

  toggleComponentFilter(
    column: ComponentColumnFilterKey,
    event?: MouseEvent
  ): void {
    event?.stopPropagation();
    this.componentFilterVisible.set(toggleVisibility(this.componentFilterVisible(), column));
  }

  toggleComponentFilterPanel(): void {
    const next = !this.componentFilterPanelOpen();
    this.componentFilterPanelOpen.set(next);
    this.componentFilterVisible.set(
      next
        ? enableAllVisibility(this.componentFilterVisible())
        : visibilityFromValues(this.componentHeaderFilters())
    );
  }

  toggleComponentTablePanel(): void {
    const next = !this.componentTablePanelOpen();
    this.componentTablePanelOpen.set(next);
  }

  setComponentColumnQuery(event: Event): void {
    const target = event.target as HTMLInputElement | null;
    this.componentColumnQuery.set(target?.value ?? '');
  }

  addComponentColumn(column: ComponentColumnKey): void {
    if (!column) {
      return;
    }
    const current = this.componentColumnOrder();
    if (current.includes(column)) {
      this.componentColumnQuery.set('');
      return;
    }
    this.componentColumnOrder.set([...current, column]);
    this.componentColumnQuery.set('');
  }

  removeComponentColumn(column: ComponentColumnKey): void {
    if (column === 'purl') {
      return;
    }
    const next = this.componentColumnOrder().filter((key) => key !== column);
    if (next.length === 0) {
      return;
    }
    this.componentColumnOrder.set(next);
  }

  dropComponentColumn(event: CdkDragDrop<ComponentColumnKey[]>): void {
    if (event.previousIndex === event.currentIndex) {
      return;
    }
    const next = [...this.componentColumnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.componentColumnOrder.set(next);
  }

  componentColumnLabel(column: ComponentColumnKey): string {
    return this.componentColumnDefinitions.find((def) => def.key === column)?.label ?? column;
  }

  componentColumnFilterKey(column: ComponentColumnKey): ComponentColumnFilterKey {
    return (
      this.componentColumnDefinitions.find((def) => def.key === column)?.filterKey ?? 'purl'
    );
  }

  componentColumnClass(column: ComponentColumnKey): string {
    return (
      this.componentColumnDefinitions.find((def) => def.key === column)?.className ?? ''
    );
  }

  getComponentMalwareResult(componentPurl: string): MalwareResultSummary | null {
    const value = this.componentMalwareResults().get(componentPurl);
    return value === undefined ? null : value;
  }

  getComponentMalwareStatus(componentPurl: string): LoadState {
    return this.componentMalwareStatus().get(componentPurl) ?? 'idle';
  }

  getComponentMalwarePurls(componentPurl: string): string[] {
    return this.componentMalwareMappings().get(componentPurl) ?? [];
  }

  componentMalwareTooltip(componentPurl: string | null | undefined): string {
    const purl = (componentPurl ?? '').trim();
    if (!purl) {
      return '';
    }
    const matches = this.getComponentMalwarePurls(purl);
    if (matches.length === 0) {
      return '';
    }
    return matches.join('\n');
  }

  private async ensureComponentMalwareResult(componentPurl: string): Promise<void> {
    if (!componentPurl) {
      return;
    }
    const status = this.getComponentMalwareStatus(componentPurl);
    if (status !== 'idle') {
      return;
    }
    this.componentMalwareStatus.set(
      mapSetValue(this.componentMalwareStatus(), componentPurl, 'loading')
    );
    try {
      const [mappings, queueItems] = await Promise.all([
        this.malwareApi.listFindings(componentPurl),
        this.malwareApi.listQueue(componentPurl)
      ]);
      const malwarePurls = mappings
        .map((mapping) => mapping.malwarePurl)
        .filter((purl) => purl && purl.length > 0);
      this.componentMalwareMappings.set(
        mapSetValue(this.componentMalwareMappings(), componentPurl, malwarePurls)
      );
      let result: MalwareResultSummary | null = null;
      if (malwarePurls.length > 0) {
        try {
          const items = await this.malwareApi.listMalwareResults(malwarePurls[0]);
          result = items[0] ?? null;
        } catch {
          // Fall back to queue/mapping-based summary when explorer results are unavailable.
        }
      }
      if (!result) {
        result = this.buildFallbackComponentMalwareResult(componentPurl, malwarePurls, queueItems);
      }
      this.componentMalwareResults.set(
        mapSetValue(this.componentMalwareResults(), componentPurl, result)
      );
      this.componentMalwareStatus.set(
        mapSetValue(this.componentMalwareStatus(), componentPurl, 'loaded')
      );
    } catch (error) {
      this.errorHandler.handleError(error);
      this.componentMalwareStatus.set(
        mapSetValue(this.componentMalwareStatus(), componentPurl, 'error')
      );
    }
  }

  private buildFallbackComponentMalwareResult(
    componentPurl: string,
    malwarePurls: string[],
    queueItems: ComponentAnalysisQueueItem[]
  ): MalwareResultSummary {
    const latestCompleted = queueItems.find((item) => item.status === 'COMPLETED') ?? null;
    const verdict: MalwareResultSummary['verdict'] =
      malwarePurls.length > 0 ? 'MALWARE' : latestCompleted ? 'CLEAN' : 'UNKNOWN';
    return {
      id: `fallback:${componentPurl}`,
      componentPurl,
      verdict,
      findingsCount: malwarePurls.length > 0 ? malwarePurls.length : verdict === 'UNKNOWN' ? null : 0,
      scannedAt:
        latestCompleted?.completedAt ??
        latestCompleted?.updatedAt ??
        latestCompleted?.createdAt ??
        null,
      validUntil: null
    };
  }

  componentColumnValue(component: ComponentSummary, column: ComponentColumnKey): string {
    switch (column) {
      case 'purl':
        return this.decodePurl(component.purl ?? '-');
      case 'pkgType':
        return component.pkgType ?? '-';
      case 'pkgName':
        return component.pkgName ?? '-';
      case 'version':
        return component.version ?? '-';
      case 'pkgNamespace':
        return component.pkgNamespace ?? '-';
      case 'licenses':
        return this.formatLicensesDetail(component.licenses);
      case 'sbomType':
        return component.sbomType ?? '-';
      case 'publisher':
        return component.publisher ?? '-';
      case 'supplier':
        return component.supplier ?? '-';
      case 'malwareVerdict': {
        const purl = (component.purl ?? '').trim();
        if (!purl) {
          return '-';
        }
        this.ensureComponentMalwareResultForCell(purl);
        const result = this.getComponentMalwareResult(purl);
        if (result?.verdict) {
          return result.verdict;
        }
        return 'UNKNOWN';
      }
      case 'malwareScannedAt': {
        const purl = (component.purl ?? '').trim();
        this.ensureComponentMalwareResultForCell(purl);
        const result = this.getComponentMalwareResult(purl);
        return result?.scannedAt ?? '-';
      }
      case 'malwareValidUntil': {
        const purl = (component.purl ?? '').trim();
        this.ensureComponentMalwareResultForCell(purl);
        const result = this.getComponentMalwareResult(purl);
        return result?.validUntil ?? '-';
      }
    }
  }

  private ensureComponentMalwareResultForCell(componentPurl: string): void {
    if (!componentPurl) {
      return;
    }
    if (this.getComponentMalwareStatus(componentPurl) !== 'idle') {
      return;
    }
    void this.ensureComponentMalwareResult(componentPurl);
  }

  productColumnValue(
    product: ProductSummary & { scopesCount?: number | null },
    column: ProductColumnKey
  ): string {
    switch (column) {
      case 'name':
        return product.name ?? '-';
      case 'scopes':
        return String(product.scopesCount ?? '-');
      case 'updated':
        return product.updatedAt ?? '-';
    }
  }

  scopeColumnValue(scope: ScopeSummary & { testsCount?: number | null }, column: ScopeColumnKey): string {
    switch (column) {
      case 'name':
        return scope.name ?? '-';
      case 'tests':
        return String(scope.testsCount ?? '-');
      case 'updated':
        return scope.updatedAt ?? '-';
    }
  }

  testColumnValue(
    test: TestSummary & { componentsCount?: number | null },
    column: TestColumnKey
  ): string {
    switch (column) {
      case 'name':
        return test.name ?? '-';
      case 'id':
        return test.id ?? '-';
      case 'components':
        return String(test.componentsCount ?? '-');
      case 'updated':
        return test.updatedAt ?? '-';
    }
  }

  revisionColumnValue(revision: TestRevisionSummary, column: RevisionColumnKey): string {
    switch (column) {
      case 'revision':
        return this.formatShortId(revision.id);
      case 'sbomSha':
        return this.formatShortId(revision.sbomSha256 ?? '-');
      case 'producer':
        return revision.sbomProducer ?? '-';
      case 'tags':
        return this.formatTags(revision.tags ?? []);
      case 'components':
        return String(revision.componentsImportedCount ?? 0);
      case 'active':
        return revision.isActive ? 'Yes' : 'No';
      case 'lastModified':
        return revision.lastModifiedAt ?? revision.createdAt ?? '-';
    }
  }

  lastChangeColumnValue(row: TestRevisionChangeSummary, column: LastChangeColumnKey): string {
    switch (column) {
      case 'toRevision':
        return this.formatShortId(row.toRevisionId);
      case 'fromRevision':
        return this.formatShortId(row.fromRevisionId ?? '-');
      case 'status':
        return (row.status ?? '-').toUpperCase();
      case 'added':
        return String(row.addedCount ?? 0);
      case 'removed':
        return String(row.removedCount ?? 0);
      case 'reappeared':
        return String(row.reappearedCount ?? 0);
      case 'unchanged':
        return String(row.unchangedCount ?? 0);
      case 'computedAt':
        return row.computedAt ?? '-';
      case 'createdAt':
        return row.createdAt ?? '-';
    }
  }

  revisionChangeColumnValue(row: TestRevisionFindingDiff, column: RevisionChangeColumnKey): string {
    switch (column) {
      case 'diffType':
        return (row.diffType ?? '-').toUpperCase();
      case 'findingType':
        return row.findingType ?? '-';
      case 'componentPurl':
        return this.decodePurl(row.componentPurl ?? '-');
      case 'malwarePurl':
        return this.decodePurl(row.malwarePurl ?? '-');
      case 'createdAt':
        return row.createdAt ?? '-';
    }
  }

  setProductColumnFilter(column: ProductColumnKey, event: Event): void {
    this.productColumnFilters.set(setFilterValue(this.productColumnFilters(), column, event));
  }

  setScopeColumnFilter(column: ScopeColumnKey, event: Event): void {
    this.scopeColumnFilters.set(setFilterValue(this.scopeColumnFilters(), column, event));
  }

  setTestColumnFilter(column: TestColumnKey, event: Event): void {
    this.testColumnFilters.set(setFilterValue(this.testColumnFilters(), column, event));
  }

  setRevisionColumnFilter(
    column: RevisionColumnKey,
    event: Event
  ): void {
    this.revisionColumnFilters.set(setFilterValue(this.revisionColumnFilters(), column, event));
  }

  setLastChangeColumnFilter(column: LastChangeColumnKey, event: Event): void {
    this.lastChangeColumnFilters.set(setFilterValue(this.lastChangeColumnFilters(), column, event));
  }

  setRevisionChangeColumnFilter(column: RevisionChangeColumnKey, event: Event): void {
    this.revisionChangeColumnFilters.set(
      setFilterValue(this.revisionChangeColumnFilters(), column, event)
    );
  }

  setComponentColumnFilter(
    column: ComponentColumnFilterKey,
    event: Event
  ): void {
    this.componentColumnFilters.set(setFilterValue(this.componentColumnFilters(), column, event));
  }

  setComponentFilterValue(
    column: ComponentColumnFilterKey,
    value: string
  ): void {
    this.componentColumnFilters.set({ ...this.componentColumnFilters(), [column]: value });
  }

  setComponentFilterMode(
    column: ComponentColumnFilterKey,
    mode: 'contains' | 'select'
  ): void {
    this.componentFilterMode.set({ ...this.componentFilterMode(), [column]: mode });
  }

  setComponentMultiFilter(
    column: 'type' | 'namespace' | 'licenses' | 'sbomType' | 'publisher' | 'supplier',
    values: string[]
  ): void {
    this.componentMultiFilters.set({ ...this.componentMultiFilters(), [column]: values });
  }

  setProductFilterMode(
    column: 'name' | 'scopes' | 'updated',
    mode: 'contains' | 'select'
  ): void {
    this.productFilterMode.set({ ...this.productFilterMode(), [column]: mode });
  }

  setProductMultiFilter(
    column: 'name' | 'scopes' | 'updated',
    values: string[]
  ): void {
    this.productMultiFilters.set({ ...this.productMultiFilters(), [column]: values });
  }

  setScopeFilterMode(
    column: 'name' | 'tests' | 'updated',
    mode: 'contains' | 'select'
  ): void {
    this.scopeFilterMode.set({ ...this.scopeFilterMode(), [column]: mode });
  }

  setScopeMultiFilter(
    column: 'name' | 'tests' | 'updated',
    values: string[]
  ): void {
    this.scopeMultiFilters.set({ ...this.scopeMultiFilters(), [column]: values });
  }

  setTestFilterMode(
    column: 'name' | 'id' | 'components' | 'updated',
    mode: 'contains' | 'select'
  ): void {
    this.testFilterMode.set({ ...this.testFilterMode(), [column]: mode });
  }

  setTestMultiFilter(
    column: 'name' | 'id' | 'components' | 'updated',
    values: string[]
  ): void {
    this.testMultiFilters.set({ ...this.testMultiFilters(), [column]: values });
  }

  setRevisionFilterMode(
    column: 'revision' | 'sbomSha' | 'producer' | 'tags' | 'components' | 'active' | 'lastModified',
    mode: 'contains' | 'select'
  ): void {
    this.revisionFilterMode.set({ ...this.revisionFilterMode(), [column]: mode });
  }

  setRevisionMultiFilter(
    column: 'revision' | 'sbomSha' | 'producer' | 'tags' | 'components' | 'active' | 'lastModified',
    values: string[]
  ): void {
    this.revisionMultiFilters.set({ ...this.revisionMultiFilters(), [column]: values });
  }

  clearProductFilters(): void {
    this.productColumnFilters.set(this.emptyProductFilters());
    this.productMultiFilters.set({ name: [], scopes: [], updated: [] });
    this.productFilterMode.set({ name: 'contains', scopes: 'contains', updated: 'contains' });
  }

  clearScopeFilters(): void {
    this.scopeColumnFilters.set(this.emptyScopeFilters());
    this.scopeMultiFilters.set({ name: [], tests: [], updated: [] });
    this.scopeFilterMode.set({ name: 'contains', tests: 'contains', updated: 'contains' });
  }

  clearTestFilters(): void {
    this.testColumnFilters.set(this.emptyTestFilters());
    this.testMultiFilters.set({ name: [], id: [], components: [], updated: [] });
    this.testFilterMode.set({ name: 'contains', id: 'contains', components: 'contains', updated: 'contains' });
  }

  clearRevisionFilters(): void {
    this.revisionColumnFilters.set(this.emptyRevisionFilters());
    this.revisionMultiFilters.set({
      revision: [],
      sbomSha: [],
      producer: [],
      tags: [],
      components: [],
      active: [],
      lastModified: []
    });
    this.revisionFilterMode.set({
      revision: 'contains',
      sbomSha: 'contains',
      producer: 'contains',
      tags: 'contains',
      components: 'contains',
      active: 'contains',
      lastModified: 'contains'
    });
  }

  clearLastChangeFilters(): void {
    this.lastChangeColumnFilters.set(this.emptyLastChangeFilters());
  }

  clearRevisionChangeFilters(): void {
    this.revisionChangeColumnFilters.set(this.emptyRevisionChangeFilters());
  }

  clearComponentFilters(): void {
    this.componentColumnFilters.set(this.emptyComponentFilters());
    this.componentMultiFilters.set({
      type: [],
      namespace: [],
      licenses: [],
      sbomType: [],
      publisher: [],
      supplier: []
    });
    this.componentFilterMode.set({
      purl: 'contains',
      type: 'contains',
      name: 'contains',
      version: 'contains',
      namespace: 'contains',
      licenses: 'contains',
      sbomType: 'contains',
      publisher: 'contains',
      supplier: 'contains',
      malwareVerdict: 'contains',
      malwareScannedAt: 'contains',
      malwareValidUntil: 'contains'
    });
  }

  toggleProductSort(column: ProductColumnKey): void {
    toggleSort(this.productSortColumn, this.productSortDir, column, column === 'name' ? 'asc' : 'desc');
  }

  toggleScopeSort(column: ScopeColumnKey): void {
    toggleSort(this.scopeSortColumn, this.scopeSortDir, column, column === 'name' ? 'asc' : 'desc');
  }

  toggleTestSort(column: TestColumnKey): void {
    const defaultDir = column === 'name' || column === 'id' ? 'asc' : 'desc';
    toggleSort(this.testSortColumn, this.testSortDir, column, defaultDir);
  }

  toggleRevisionSort(column: RevisionColumnKey): void {
    const defaultDir = column === 'revision' || column === 'producer' || column === 'tags' ? 'asc' : 'desc';
    toggleSort(this.revisionSortColumn, this.revisionSortDir, column, defaultDir);
  }

  toggleLastChangeSort(column: LastChangeColumnKey): void {
    const defaultDir = column === 'toRevision' || column === 'fromRevision' || column === 'status' ? 'asc' : 'desc';
    toggleSort(this.lastChangeSortColumn, this.lastChangeSortDir, column, defaultDir);
  }

  toggleRevisionChangeSort(column: RevisionChangeColumnKey): void {
    const defaultDir = column === 'diffType' || column === 'findingType' ? 'asc' : 'desc';
    toggleSort(this.revisionChangeSortColumn, this.revisionChangeSortDir, column, defaultDir);
  }

  toggleComponentSort(column: ComponentColumnKey): void {
    const defaultDir = column === 'purl' || column === 'pkgName' ? 'asc' : 'desc';
    toggleSort(this.componentSortColumn, this.componentSortDir, column, defaultDir);
  }

  sortIndicator<T extends string>(column: T, activeColumn: T, dir: 'asc' | 'desc'): string {
    if (column !== activeColumn) {
      return '';
    }
    return dir === 'asc' ? '▲' : '▼';
  }

  setProductPageSize(size: number): void {
    this.productPageSize.set(size);
    this.productPageIndex.set(0);
  }

  setScopePageSize(size: number): void {
    this.scopePageSize.set(size);
    this.scopePageIndex.set(0);
  }

  setTestPageSize(size: number): void {
    this.testPageSize.set(size);
    this.testPageIndex.set(0);
  }

  setRevisionPageSize(size: number): void {
    this.revisionPageSize.set(size);
    this.revisionPageIndex.set(0);
  }

  setLastChangePageSize(size: number): void {
    this.lastChangePageSize.set(size);
    this.lastChangePageIndex.set(0);
  }

  setRevisionChangePageSize(size: number): void {
    this.revisionChangePageSize.set(size);
    this.revisionChangePageIndex.set(0);
  }

  setComponentPageSize(size: number): void {
    this.componentPageSize.set(size);
    this.componentPageIndex.set(0);
  }

  loadAllComponents(): void {
    const testId = this.selectedTestId();
    if (!testId || this.componentsLoadedAll()) {
      return;
    }

    // Switch from preview mode (first N) to full table behaviour.
    this.componentLoadMode.set('all');
    this.componentPageIndex.set(0);
    const currentPageSize = this.componentPageSize();
    const normalizedPageSize = this.pageSizeOptions.includes(currentPageSize) ? currentPageSize : 10;
    this.componentPageSize.set(normalizedPageSize);
    this.componentFilterPanelOpen.set(false);
    this.componentTablePanelOpen.set(false);
    this.expandedComponents.set(new Set());

    void this.store.reloadComponentsAll(testId);
  }

  prevProductPage(): void {
    this.productPageIndex.set(Math.max(0, this.productPageIndex() - 1));
  }

  nextProductPage(): void {
    const totalPages = this.totalPages(this.productTotal(), this.productPageSize());
    this.productPageIndex.set(Math.min(totalPages - 1, this.productPageIndex() + 1));
  }

  prevScopePage(): void {
    this.scopePageIndex.set(Math.max(0, this.scopePageIndex() - 1));
  }

  nextScopePage(): void {
    const totalPages = this.totalPages(this.scopeTotal(), this.scopePageSize());
    this.scopePageIndex.set(Math.min(totalPages - 1, this.scopePageIndex() + 1));
  }

  prevTestPage(): void {
    this.testPageIndex.set(Math.max(0, this.testPageIndex() - 1));
  }

  nextTestPage(): void {
    const totalPages = this.totalPages(this.testTotal(), this.testPageSize());
    this.testPageIndex.set(Math.min(totalPages - 1, this.testPageIndex() + 1));
  }

  prevRevisionPage(): void {
    this.revisionPageIndex.set(Math.max(0, this.revisionPageIndex() - 1));
  }

  nextRevisionPage(): void {
    const totalPages = this.totalPages(this.revisionTotal(), this.revisionPageSize());
    this.revisionPageIndex.set(Math.min(totalPages - 1, this.revisionPageIndex() + 1));
  }

  prevLastChangePage(): void {
    this.lastChangePageIndex.set(Math.max(0, this.lastChangePageIndex() - 1));
  }

  nextLastChangePage(): void {
    const totalPages = this.totalPages(this.lastChangeTotal(), this.lastChangePageSize());
    this.lastChangePageIndex.set(Math.min(totalPages - 1, this.lastChangePageIndex() + 1));
  }

  prevRevisionChangePage(): void {
    this.revisionChangePageIndex.set(Math.max(0, this.revisionChangePageIndex() - 1));
  }

  nextRevisionChangePage(): void {
    const totalPages = this.totalPages(this.revisionChangeTotal(), this.revisionChangePageSize());
    this.revisionChangePageIndex.set(Math.min(totalPages - 1, this.revisionChangePageIndex() + 1));
  }

  prevComponentPage(): void {
    this.componentPageIndex.set(Math.max(0, this.componentPageIndex() - 1));
  }

  nextComponentPage(): void {
    const totalPages = this.componentTotalPages();
    this.componentPageIndex.set(Math.min(totalPages - 1, this.componentPageIndex() + 1));
  }

  formatTags(tags: string[] | null | undefined): string {
    if (!tags || tags.length === 0) {
      return '-';
    }
    return tags.join(', ');
  }

  formatShortId(value: string | null | undefined): string {
    if (!value) {
      return '-';
    }
    return value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
  }

  filterInputSize(value: string | null | undefined): number {
    const normalized = (value ?? '').trim();
    if (!normalized) {
      return 8;
    }
    return Math.max(6, Math.min(normalized.length + 2, 24));
  }

  formatSbom(test: TestSummary | null): string {
    if (!test?.sbomType) {
      return '-';
    }
    return `${test.sbomType.standard} ${test.sbomType.specVersion}`.trim();
  }

  getScopesCount(productId: string): string {
    const count = this.store.getScopesCount(productId);
    return count === null ? '-' : String(count);
  }

  getTestsCount(scopeId: string): string {
    const count = this.store.getTestsCount(scopeId);
    return count === null ? '-' : String(count);
  }

  getComponentsCount(testId: string): string {
    const count = this.store.getComponentsCount(testId);
    return count === null ? '-' : String(count);
  }

  decodePurl(value?: string | null): string {
    if (!value) {
      return '-';
    }
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  async copyValue(value: string | null | undefined): Promise<void> {
    await this.clipboard.copyText(value);
  }

  toggleComponent(componentId: string): void {
    const next = new Set(this.expandedComponents());
    if (next.has(componentId)) {
      next.delete(componentId);
    } else {
      next.add(componentId);
    }
    this.expandedComponents.set(next);
  }

  componentExpandedIds(): ReadonlySet<string> {
    return this.expandedComponents();
  }

  isComponentExpanded(componentId: string): boolean {
    return this.expandedComponents().has(componentId);
  }

  toggleRevision(revisionId: string): void {
    const next = new Set(this.expandedRevisions());
    if (next.has(revisionId)) {
      next.delete(revisionId);
    } else {
      next.add(revisionId);
    }
    this.expandedRevisions.set(next);
  }

  isRevisionExpanded(revisionId: string): boolean {
    return this.expandedRevisions().has(revisionId);
  }

  openRevisionChanges(revisionId: string | null): void {
    const normalized = (revisionId ?? '').trim();
    if (!normalized) {
      this.selectedRevisionChangeId.set(null);
      this.revisionChangePageIndex.set(0);
      return;
    }
    if (this.selectedRevisionChangeId() === normalized) {
      this.selectedRevisionChangeId.set(null);
      this.revisionChangePageIndex.set(0);
      return;
    }
    this.selectedRevisionChangeId.set(normalized);
    this.revisionChangePageIndex.set(0);
  }

  selectedRevisionChangeExpandedIds(): string[] {
    const id = this.selectedRevisionChangeId();
    return id ? [id] : [];
  }

  isRevisionChangeSelected(revisionId: string | null | undefined): boolean {
    if (!revisionId) {
      return false;
    }
    return this.selectedRevisionChangeId() === revisionId;
  }

  formatLicensesDetail(licenses: unknown): string {
    return formatLicensesDetailValue(licenses);
  }

  private filterComponents(rows: ComponentSummary[]): ComponentSummary[] {
    const state: DataComponentFilterState = {
      filters: this.componentColumnFilters(),
      modes: this.componentFilterMode(),
      multi: this.componentMultiFilters()
    };
    return filterComponentRows(rows, state, (componentPurl) =>
      this.getComponentMalwareResult(componentPurl)
    );
  }

  hasLicenses(licenses: unknown): boolean {
    return hasLicensesValue(licenses);
  }

  hasRevisions(): boolean {
    return this.revisions().length > 0;
  }

  hasComponents(): boolean {
    return this.components().length > 0;
  }

  hasLastChanges(): boolean {
    return this.revisionLastChanges().length > 0;
  }

  selectedRevisionChangeStatusLabel(): string {
    return (this.selectedRevisionChangeSummary()?.status ?? '-').toUpperCase();
  }

  lastChangesTableStatus(): 'loading' | 'error' | 'loaded' {
    const status = this.revisionLastChangesStatus();
    if (status === 'loading' || status === 'error') {
      return status;
    }
    return 'loaded';
  }

  revisionChangesTableStatus(): 'loading' | 'error' | 'loaded' {
    const selectedSummary = this.selectedRevisionChangeSummary();
    const summaryStatus = (selectedSummary?.status ?? '').toUpperCase();
    if (summaryStatus === 'PENDING' || summaryStatus === 'PROCESSING') {
      return 'loading';
    }
    if (summaryStatus === 'FAILED') {
      return 'error';
    }
    const status = this.revisionChangesStatus();
    if (status === 'loading' || status === 'error') {
      return status;
    }
    return 'loaded';
  }

  revisionChangesLoadingMessage(): string {
    const status = (this.selectedRevisionChangeSummary()?.status ?? '').toUpperCase();
    if (status === 'PENDING' || status === 'PROCESSING') {
      return 'Reimport diff is still processing...';
    }
    return 'Loading revision changes...';
  }

  revisionChangesErrorMessage(): string {
    const status = (this.selectedRevisionChangeSummary()?.status ?? '').toUpperCase();
    if (status === 'FAILED') {
      return 'Revision diff computation failed. Check Events for details.';
    }
    return 'Failed to load revision changes.';
  }


  private getExpandedState(section: DataSection): ExpandState {
    switch (section) {
      case 'products':
        return this.expandedProducts();
      case 'scopes':
        return this.expandedScopes();
      case 'tests':
        return this.expandedTests();
    }
  }

  private setExpandedState(section: DataSection, state: ExpandState): void {
    switch (section) {
      case 'products':
        this.expandedProducts.set(state);
        return;
      case 'scopes':
        this.expandedScopes.set(state);
        return;
      case 'tests':
        this.expandedTests.set(state);
    }
  }

  private startRevisionChangesPolling(testId: string): void {
    if (this.revisionChangesPollHandle && this.revisionChangesPollTestId === testId) {
      return;
    }
    this.stopRevisionChangesPolling();
    this.revisionChangesPollTestId = testId;
    this.revisionChangesPollHandle = window.setInterval(() => {
      const activeTestId = this.selectedTestId();
      if (!this.isTestDetail() || !activeTestId || activeTestId !== testId) {
        this.stopRevisionChangesPolling();
        return;
      }
      void this.store.reloadRevisionLastChanges(testId, true);
      const revisionId = this.selectedRevisionChangeId();
      if (!revisionId) {
        return;
      }
      const selectedStatus = (this.selectedRevisionChangeSummary()?.status ?? '').toUpperCase();
      if (selectedStatus === 'COMPLETED' || selectedStatus === 'FAILED') {
        void this.store.reloadRevisionChangesSummary(testId, revisionId, true);
        void this.store.reloadRevisionChanges(testId, revisionId, true);
      }
    }, 5000);
  }

  private stopRevisionChangesPolling(): void {
    if (this.revisionChangesPollHandle) {
      window.clearInterval(this.revisionChangesPollHandle);
      this.revisionChangesPollHandle = null;
    }
    this.revisionChangesPollTestId = null;
  }

  private applyQueryParams(params: ParamMap): void {
    this.isSyncingFromUrl = true;

    const sectionParam = params.get('section');
    const productId = params.get('productId');
    const scopeId = params.get('scopeId');
    const testId = params.get('testId');
    const componentQ = params.get('componentQ');
    const detail = params.get('detail') === '1';
    const section: DataSection =
      detail && testId
        ? 'tests'
        : sectionParam === 'products' || sectionParam === 'scopes' || sectionParam === 'tests'
          ? sectionParam
          : 'products';

    let resolvedScopeId = scopeId;
    if (!resolvedScopeId && testId) {
      resolvedScopeId = this.store.findTest(testId)?.scopeId ?? null;
    }
    let resolvedProductId = productId;
    if (!resolvedProductId && resolvedScopeId) {
      resolvedProductId = this.store.findScope(resolvedScopeId)?.productId ?? null;
    }

    this.section.set(section);
    this.selectedProductId.set(resolvedProductId);
    this.selectedScopeId.set(resolvedScopeId);
    this.selectedTestId.set(testId);
    this.isTestDetail.set(detail && Boolean(testId));
    this.componentQ.set(detail && Boolean(testId) ? (componentQ ?? '') : '');
    this.refreshContextOnRouteEntry(section, resolvedProductId, resolvedScopeId, testId, detail && Boolean(testId));

    const activeGroups = this.getActiveFilterGroups(section, detail && Boolean(testId));

    const productFilters =
      activeGroups.product
        ? {
            name: this.readParam(params, 'pf_name'),
            scopes: this.readParam(params, 'pf_scopes'),
            updated: this.readParam(params, 'pf_updated')
          }
        : this.emptyProductFilters();
    const scopeFilters =
      activeGroups.scope
        ? {
            name: this.readParam(params, 'sf_name'),
            tests: this.readParam(params, 'sf_tests'),
            updated: this.readParam(params, 'sf_updated')
          }
        : this.emptyScopeFilters();
    const testFilters =
      activeGroups.test
        ? {
            name: this.readParam(params, 'tf_name'),
            id: this.readParam(params, 'tf_id'),
            components: this.readParam(params, 'tf_components'),
            updated: this.readParam(params, 'tf_updated')
          }
        : this.emptyTestFilters();
    const revisionFilters =
      activeGroups.revision
        ? {
            revision: this.readParam(params, 'rf_revision'),
            sbomSha: this.readParam(params, 'rf_sbomSha'),
            producer: this.readParam(params, 'rf_producer'),
            tags: this.readParam(params, 'rf_tags'),
            components: this.readParam(params, 'rf_components'),
            active: this.readParam(params, 'rf_active'),
            lastModified: this.readParam(params, 'rf_lastModified')
          }
        : this.emptyRevisionFilters();
    const componentFilters =
      activeGroups.component
        ? {
            purl: this.readParam(params, 'cf_purl'),
            type: this.readParam(params, 'cf_type'),
            name: this.readParam(params, 'cf_name'),
            version: this.readParam(params, 'cf_version'),
            namespace: this.readParam(params, 'cf_namespace'),
            licenses: this.readParam(params, 'cf_licenses'),
            sbomType: this.readParam(params, 'cf_sbomType'),
            publisher: this.readParam(params, 'cf_publisher'),
            supplier: this.readParam(params, 'cf_supplier'),
            malwareVerdict: this.readParam(params, 'cf_malwareVerdict'),
            malwareScannedAt: this.readParam(params, 'cf_malwareScannedAt'),
            malwareValidUntil: this.readParam(params, 'cf_malwareValidUntil')
          }
        : this.emptyComponentFilters();
    if (
      activeGroups.component &&
      !componentFilters.purl.trim() &&
      detail &&
      Boolean(testId) &&
      (componentQ ?? '').trim().length > 0
    ) {
      componentFilters.purl = (componentQ ?? '').trim();
    }

    this.productColumnFilters.set(productFilters);
    this.scopeColumnFilters.set(scopeFilters);
    this.testColumnFilters.set(testFilters);
    this.revisionColumnFilters.set(revisionFilters);
    this.componentColumnFilters.set(componentFilters);

    this.productFilterVisible.set(visibilityFromValues(productFilters));
    this.scopeFilterVisible.set(visibilityFromValues(scopeFilters));
    this.testFilterVisible.set(visibilityFromValues(testFilters));
    this.revisionFilterVisible.set(visibilityFromValues(revisionFilters));
    this.componentFilterVisible.set(visibilityFromValues(this.componentHeaderFilters()));

    const normalized = this.buildQueryParams();
    this.lastSyncedParams = JSON.stringify(normalized);
    this.isSyncingFromUrl = false;
  }

  private refreshContextOnRouteEntry(
    section: DataSection,
    productId: string | null,
    scopeId: string | null,
    testId: string | null,
    isDetail: boolean,
  ): void {
    const refreshKey = [section, productId ?? '', scopeId ?? '', testId ?? '', isDetail ? '1' : '0'].join('|');
    if (this.lastRefreshContextKey === refreshKey) {
      return;
    }
    this.lastRefreshContextKey = refreshKey;

    void this.store.ensureProducts();

    if (section === 'products') {
      void this.store.ensureAllScopes();
      void this.store.ensureAllTests();
      return;
    }

    if (section === 'scopes') {
      if (productId) {
        void this.store.ensureScopes(productId);
      } else {
        void this.store.ensureAllScopes();
      }
      void this.store.ensureAllTests();
      return;
    }

    if (scopeId) {
      void this.store.ensureTests(scopeId);
    } else {
      void this.store.ensureAllScopes();
      void this.store.ensureAllTests();
    }

    if (isDetail && testId) {
      void this.store.ensureRevisions(testId);
      void this.store.ensureComponentsCount(testId);
      void this.store.ensureRevisionLastChanges(testId);
    }
  }

  private buildQueryParams(): Record<string, string> {
    const params: Record<string, string> = {
      section: this.section()
    };
    const productId = this.selectedProductId();
    const scopeId = this.selectedScopeId();
    const testId = this.selectedTestId();

    if (productId) {
      params['productId'] = productId;
    }
    if (scopeId) {
      params['scopeId'] = scopeId;
    }
    if (testId) {
      params['testId'] = testId;
    }
    if (this.isTestDetail() && testId) {
      params['detail'] = '1';
    }
    const componentQ = this.componentQ().trim();
    if (this.isTestDetail() && testId && componentQ.length > 0) {
      params['componentQ'] = componentQ;
    }

    const activeGroups = this.getActiveFilterGroups(this.section(), this.isTestDetail());
    if (activeGroups.product) {
      appendFilterParams(params, 'pf_', this.productColumnFilters());
    }
    if (activeGroups.scope) {
      appendFilterParams(params, 'sf_', this.scopeColumnFilters());
    }
    if (activeGroups.test) {
      appendFilterParams(params, 'tf_', this.testColumnFilters());
    }
    if (activeGroups.revision) {
      appendFilterParams(params, 'rf_', this.revisionColumnFilters());
    }
    if (activeGroups.component) {
      appendFilterParams(params, 'cf_', this.componentColumnFilters());
    }

    return params;
  }

  private getActiveFilterGroups(section: DataSection, isDetail: boolean): {
    product: boolean;
    scope: boolean;
    test: boolean;
    revision: boolean;
    component: boolean;
  } {
    if (section === 'products') {
      return { product: true, scope: false, test: false, revision: false, component: false };
    }
    if (section === 'scopes') {
      return { product: false, scope: true, test: false, revision: false, component: false };
    }
    if (isDetail) {
      return { product: false, scope: false, test: false, revision: true, component: true };
    }
    return { product: false, scope: false, test: true, revision: false, component: false };
  }

  private emptyProductFilters(): { name: string; scopes: string; updated: string } {
    return { name: '', scopes: '', updated: '' };
  }

  private emptyScopeFilters(): { name: string; tests: string; updated: string } {
    return { name: '', tests: '', updated: '' };
  }

  private emptyTestFilters(): { name: string; id: string; components: string; updated: string } {
    return { name: '', id: '', components: '', updated: '' };
  }

  private emptyRevisionFilters(): {
    revision: string;
    sbomSha: string;
    producer: string;
    tags: string;
    components: string;
    active: string;
    lastModified: string;
  } {
    return {
      revision: '',
      sbomSha: '',
      producer: '',
      tags: '',
      components: '',
      active: '',
      lastModified: ''
    };
  }

  private emptyLastChangeFilters(): {
    toRevision: string;
    fromRevision: string;
    status: string;
    added: string;
    removed: string;
    reappeared: string;
    unchanged: string;
    computedAt: string;
    createdAt: string;
  } {
    return {
      toRevision: '',
      fromRevision: '',
      status: '',
      added: '',
      removed: '',
      reappeared: '',
      unchanged: '',
      computedAt: '',
      createdAt: ''
    };
  }

  private emptyRevisionChangeFilters(): {
    diffType: string;
    findingType: string;
    componentPurl: string;
    malwarePurl: string;
    createdAt: string;
  } {
    return {
      diffType: '',
      findingType: '',
      componentPurl: '',
      malwarePurl: '',
      createdAt: ''
    };
  }

  private emptyComponentFilters(): {
    purl: string;
    type: string;
    name: string;
    version: string;
    namespace: string;
    licenses: string;
    sbomType: string;
    publisher: string;
    supplier: string;
    malwareVerdict: string;
    malwareScannedAt: string;
    malwareValidUntil: string;
  } {
    return {
      purl: '',
      type: '',
      name: '',
      version: '',
      namespace: '',
      licenses: '',
      sbomType: '',
      publisher: '',
      supplier: '',
      malwareVerdict: '',
      malwareScannedAt: '',
      malwareValidUntil: ''
    };
  }

  private componentHeaderFilters(): {
    purl: string;
    type: string;
    name: string;
    version: string;
    namespace: string;
    licenses: string;
    sbomType: string;
    publisher: string;
    supplier: string;
    malwareVerdict: string;
    malwareScannedAt: string;
    malwareValidUntil: string;
  } {
    const filters = this.componentColumnFilters();
    return {
      purl: filters.purl,
      type: filters.type,
      name: filters.name,
      version: filters.version,
      namespace: filters.namespace,
      licenses: filters.licenses,
      sbomType: filters.sbomType,
      publisher: filters.publisher,
      supplier: filters.supplier,
      malwareVerdict: filters.malwareVerdict,
      malwareScannedAt: filters.malwareScannedAt,
      malwareValidUntil: filters.malwareValidUntil
    };
  }

  private readParam(params: ParamMap, key: string): string {
    return params.get(key) ?? '';
  }

  private resetPageOnFilterChangeSignal<T>(
    filterSignal: () => T,
    pageSignal: { set: (value: number) => void }
  ): void {
    void filterSignal();
    pageSignal.set(0);
  }

  private clampPage(
    pageSignal: { set: (value: number) => void; (): number },
    totalSignal: () => number,
    pageSizeSignal: () => number
  ): void {
    const totalPages = this.totalPages(totalSignal(), pageSizeSignal());
    const index = pageSignal();
    if (index > totalPages - 1) {
      pageSignal.set(Math.max(totalPages - 1, 0));
    }
  }

  totalPages(total: number, pageSize: number): number {
    if (pageSize <= 0) {
      return 1;
    }
    return Math.max(1, Math.ceil(total / pageSize));
  }
}
