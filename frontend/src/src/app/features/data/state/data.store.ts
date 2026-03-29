import { ErrorHandler, Injectable, computed, inject, signal, untracked } from '@angular/core';
import { DataApi } from '../data-access/data.api';
import {
  ComponentSummary,
  ProductSummary,
  ScopeSummary,
  TestRevisionChangeSummary,
  TestRevisionFindingDiff,
  TestRevisionSummary,
  TestSummary
} from '../data-access/data.types';
import { mapGetValue, mapSetValue } from '../../../shared/utils/map-utils';
import { LoadState } from '../../../shared/types/load-state';


const revisionChangesKey = (testId: string, revisionId: string): string => `${testId}::${revisionId}`;

@Injectable({ providedIn: 'root' })
export class DataStore {
  private readonly productsState = signal<ProductSummary[]>([]);
  private readonly productsStatus = signal<LoadState>('idle');

  private readonly scopesState = signal<Map<string, ScopeSummary[]>>(new Map());
  private readonly scopesStatus = signal<Map<string, LoadState>>(new Map());
  private readonly allScopesState = signal<ScopeSummary[]>([]);
  private readonly allScopesStatus = signal<LoadState>('idle');

  private readonly testsState = signal<Map<string, TestSummary[]>>(new Map());
  private readonly testsStatus = signal<Map<string, LoadState>>(new Map());
  private readonly allTestsState = signal<TestSummary[]>([]);
  private readonly allTestsStatus = signal<LoadState>('idle');

  private readonly revisionsState = signal<Map<string, TestRevisionSummary[]>>(new Map());
  private readonly revisionsStatus = signal<Map<string, LoadState>>(new Map());
  private readonly revisionLastChangesState = signal<Map<string, TestRevisionChangeSummary[]>>(new Map());
  private readonly revisionLastChangesStatus = signal<Map<string, LoadState>>(new Map());
  private readonly revisionChangesState = signal<Map<string, TestRevisionFindingDiff[]>>(new Map());
  private readonly revisionChangesStatus = signal<Map<string, LoadState>>(new Map());
  private readonly revisionChangesSummaryState = signal<Map<string, TestRevisionChangeSummary | null>>(new Map());
  private readonly revisionChangesSummaryStatus = signal<Map<string, LoadState>>(new Map());

  private readonly componentsState = signal<Map<string, ComponentSummary[]>>(new Map());
  private readonly componentsStatus = signal<Map<string, LoadState>>(new Map());
  private readonly componentsLoadedAll = signal<Map<string, boolean>>(new Map());
  private readonly componentsCountState = signal<Map<string, number>>(new Map());
  private readonly componentsCountStatus = signal<Map<string, LoadState>>(new Map());

  readonly products = computed(() => this.productsState());
  readonly productsLoadState = computed(() => this.productsStatus());

  private readonly api = inject(DataApi);
  private readonly errorHandler = inject(ErrorHandler);

  private handleSilentLoadError(statusBefore: LoadState, error: unknown): void {
    if (statusBefore === 'idle') {
      this.errorHandler.handleError(error);
    }
  }

  async ensureProducts(): Promise<void> {
    const status = untracked(() => this.productsStatus());
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadProducts();
  }

  async reloadProducts(silent = false): Promise<void> {
    const statusBefore = this.productsStatus();
    if (!silent) {
      this.productsStatus.set('loading');
    }

    try {
      const items = await this.api.getProducts();
      this.productsState.set(items);
      this.productsStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.productsStatus.set('error');
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getScopes(productId: string): ScopeSummary[] {
    return mapGetValue(this.scopesState(), productId) ?? [];
  }

  getScopesStatus(productId: string): LoadState {
    return mapGetValue(this.scopesStatus(), productId) ?? 'idle';
  }

  async ensureScopes(productId: string): Promise<void> {
    const status = untracked(() => this.getScopesStatus(productId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadScopes(productId);
  }

  async reloadScopes(productId: string, silent = false): Promise<void> {
    const statusBefore = this.getScopesStatus(productId);
    if (!silent) {
      this.scopesStatus.set(mapSetValue(this.scopesStatus(), productId, 'loading'));
    }

    try {
      const items = await this.api.getScopes(productId);
      this.scopesState.set(mapSetValue(this.scopesState(), productId, items));
      this.scopesStatus.set(mapSetValue(this.scopesStatus(), productId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.scopesStatus.set(mapSetValue(this.scopesStatus(), productId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getAllScopes(): ScopeSummary[] {
    return this.allScopesState();
  }

  getAllScopesStatus(): LoadState {
    return this.allScopesStatus();
  }

  async ensureAllScopes(): Promise<void> {
    const status = untracked(() => this.allScopesStatus());
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadAllScopes();
  }

  async reloadAllScopes(silent = false): Promise<void> {
    const statusBefore = this.allScopesStatus();
    if (!silent) {
      this.allScopesStatus.set('loading');
    }

    try {
      const items = await this.api.getAllScopes();
      this.allScopesState.set(items);
      this.allScopesStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.allScopesStatus.set('error');
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getTests(scopeId: string): TestSummary[] {
    return mapGetValue(this.testsState(), scopeId) ?? [];
  }

  getTestsStatus(scopeId: string): LoadState {
    return mapGetValue(this.testsStatus(), scopeId) ?? 'idle';
  }

  async ensureTests(scopeId: string): Promise<void> {
    const status = untracked(() => this.getTestsStatus(scopeId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadTests(scopeId);
  }

  async reloadTests(scopeId: string, silent = false): Promise<void> {
    const statusBefore = this.getTestsStatus(scopeId);
    if (!silent) {
      this.testsStatus.set(mapSetValue(this.testsStatus(), scopeId, 'loading'));
    }

    try {
      const items = await this.api.getTests(scopeId);
      this.testsState.set(mapSetValue(this.testsState(), scopeId, items));
      this.testsStatus.set(mapSetValue(this.testsStatus(), scopeId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.testsStatus.set(mapSetValue(this.testsStatus(), scopeId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getAllTests(): TestSummary[] {
    return this.allTestsState();
  }

  getAllTestsStatus(): LoadState {
    return this.allTestsStatus();
  }

  async ensureAllTests(): Promise<void> {
    const status = untracked(() => this.allTestsStatus());
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadAllTests();
  }

  async reloadAllTests(silent = false): Promise<void> {
    const statusBefore = this.allTestsStatus();
    if (!silent) {
      this.allTestsStatus.set('loading');
    }

    try {
      const items = await this.api.getAllTests();
      this.allTestsState.set(items);
      this.allTestsStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.allTestsStatus.set('error');
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  findScope(scopeId: string): ScopeSummary | null {
    for (const scopes of this.scopesState().values()) {
      const match = scopes.find((scope) => scope.id === scopeId);
      if (match) {
        return match;
      }
    }
    return this.allScopesState().find((scope) => scope.id === scopeId) ?? null;
  }

  findProduct(productId: string): ProductSummary | null {
    return this.productsState().find((product) => product.id === productId) ?? null;
  }

  findTest(testId: string): TestSummary | null {
    for (const tests of this.testsState().values()) {
      const match = tests.find((test) => test.id === testId);
      if (match) {
        return match;
      }
    }
    return this.allTestsState().find((test) => test.id === testId) ?? null;
  }

  getRevisions(testId: string): TestRevisionSummary[] {
    return mapGetValue(this.revisionsState(), testId) ?? [];
  }

  getScopesCount(productId: string): number | null {
    const scopes = this.allScopesState();
    if (scopes.length === 0) {
      return null;
    }
    return scopes.filter((scope) => scope.productId === productId).length;
  }

  getTestsCount(scopeId: string): number | null {
    const tests = this.allTestsState();
    if (tests.length === 0) {
      return null;
    }
    return tests.filter((test) => test.scopeId === scopeId).length;
  }

  getComponentsCount(testId: string): number | null {
    const apiCount = mapGetValue(this.componentsCountState(), testId);
    if (typeof apiCount === 'number') {
      return apiCount;
    }
    const revisions = mapGetValue(this.revisionsState(), testId);
    if (!revisions || revisions.length === 0) {
      return null;
    }
    const active = revisions.find((revision) => revision.isActive);
    if (active?.componentsImportedCount !== undefined && active.componentsImportedCount !== null) {
      return active.componentsImportedCount;
    }
    let latest: TestRevisionSummary | null = null;
    for (const revision of revisions) {
      if (!latest) {
        latest = revision;
        continue;
      }
      const currentTime = revision.lastModifiedAt ?? revision.createdAt ?? '';
      const latestTime = latest.lastModifiedAt ?? latest.createdAt ?? '';
      if (currentTime > latestTime) {
        latest = revision;
      }
    }
    return latest?.componentsImportedCount ?? null;
  }

  getRevisionsStatus(testId: string): LoadState {
    return mapGetValue(this.revisionsStatus(), testId) ?? 'idle';
  }

  async ensureRevisions(testId: string): Promise<void> {
    const status = untracked(() => this.getRevisionsStatus(testId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadRevisions(testId);
  }

  async reloadRevisions(testId: string, silent = false): Promise<void> {
    const statusBefore = this.getRevisionsStatus(testId);
    if (!silent) {
      this.revisionsStatus.set(mapSetValue(this.revisionsStatus(), testId, 'loading'));
    }
    try {
      const items = await this.api.getRevisions(testId);
      this.revisionsState.set(mapSetValue(this.revisionsState(), testId, items));
      this.revisionsStatus.set(mapSetValue(this.revisionsStatus(), testId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.revisionsStatus.set(mapSetValue(this.revisionsStatus(), testId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getRevisionLastChanges(testId: string): TestRevisionChangeSummary[] {
    return mapGetValue(this.revisionLastChangesState(), testId) ?? [];
  }

  getRevisionLastChangesStatus(testId: string): LoadState {
    return mapGetValue(this.revisionLastChangesStatus(), testId) ?? 'idle';
  }

  async ensureRevisionLastChanges(testId: string): Promise<void> {
    const status = untracked(() => this.getRevisionLastChangesStatus(testId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadRevisionLastChanges(testId);
  }

  async reloadRevisionLastChanges(testId: string, silent = false): Promise<void> {
    const statusBefore = this.getRevisionLastChangesStatus(testId);
    if (!silent) {
      this.revisionLastChangesStatus.set(mapSetValue(this.revisionLastChangesStatus(), testId, 'loading'));
    }
    try {
      const items = await this.api.getRevisionLastChanges(testId);
      this.revisionLastChangesState.set(mapSetValue(this.revisionLastChangesState(), testId, items));
      this.revisionLastChangesStatus.set(mapSetValue(this.revisionLastChangesStatus(), testId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.revisionLastChangesStatus.set(mapSetValue(this.revisionLastChangesStatus(), testId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getRevisionChanges(testId: string, revisionId: string): TestRevisionFindingDiff[] {
    return mapGetValue(this.revisionChangesState(), revisionChangesKey(testId, revisionId)) ?? [];
  }

  getRevisionChangesStatus(testId: string, revisionId: string): LoadState {
    return mapGetValue(this.revisionChangesStatus(), revisionChangesKey(testId, revisionId)) ?? 'idle';
  }

  async ensureRevisionChanges(testId: string, revisionId: string): Promise<void> {
    const status = untracked(() => this.getRevisionChangesStatus(testId, revisionId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadRevisionChanges(testId, revisionId);
  }

  async reloadRevisionChanges(testId: string, revisionId: string, silent = false): Promise<void> {
    const key = revisionChangesKey(testId, revisionId);
    const statusBefore = mapGetValue(this.revisionChangesStatus(), key) ?? 'idle';
    if (!silent) {
      this.revisionChangesStatus.set(mapSetValue(this.revisionChangesStatus(), key, 'loading'));
    }
    try {
      const items = await this.api.getRevisionChanges(testId, revisionId);
      this.revisionChangesState.set(mapSetValue(this.revisionChangesState(), key, items));
      this.revisionChangesStatus.set(mapSetValue(this.revisionChangesStatus(), key, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.revisionChangesStatus.set(mapSetValue(this.revisionChangesStatus(), key, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getRevisionChangesSummary(testId: string, revisionId: string): TestRevisionChangeSummary | null {
    const value = mapGetValue(this.revisionChangesSummaryState(), revisionChangesKey(testId, revisionId));
    return value ?? null;
  }

  getRevisionChangesSummaryStatus(testId: string, revisionId: string): LoadState {
    return mapGetValue(this.revisionChangesSummaryStatus(), revisionChangesKey(testId, revisionId)) ?? 'idle';
  }

  async ensureRevisionChangesSummary(testId: string, revisionId: string): Promise<void> {
    const status = untracked(() => this.getRevisionChangesSummaryStatus(testId, revisionId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadRevisionChangesSummary(testId, revisionId);
  }

  async reloadRevisionChangesSummary(testId: string, revisionId: string, silent = false): Promise<void> {
    const key = revisionChangesKey(testId, revisionId);
    const statusBefore = mapGetValue(this.revisionChangesSummaryStatus(), key) ?? 'idle';
    if (!silent) {
      this.revisionChangesSummaryStatus.set(mapSetValue(this.revisionChangesSummaryStatus(), key, 'loading'));
    }
    try {
      const item = await this.api.getRevisionChangesSummary(testId, revisionId);
      this.revisionChangesSummaryState.set(mapSetValue(this.revisionChangesSummaryState(), key, item));
      this.revisionChangesSummaryStatus.set(mapSetValue(this.revisionChangesSummaryStatus(), key, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.revisionChangesSummaryStatus.set(mapSetValue(this.revisionChangesSummaryStatus(), key, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getComponents(testId: string): ComponentSummary[] {
    return mapGetValue(this.componentsState(), testId) ?? [];
  }

  getComponentsStatus(testId: string): LoadState {
    return mapGetValue(this.componentsStatus(), testId) ?? 'idle';
  }

  getComponentsLoadedAll(testId: string): boolean {
    return mapGetValue(this.componentsLoadedAll(), testId) ?? false;
  }

  getComponentsCountFromApi(testId: string): number | null {
    const value = mapGetValue(this.componentsCountState(), testId);
    return typeof value === 'number' ? value : null;
  }

  getComponentsCountStatus(testId: string): LoadState {
    return mapGetValue(this.componentsCountStatus(), testId) ?? 'idle';
  }

  async ensureComponentsCount(testId: string): Promise<void> {
    const status = untracked(() => this.getComponentsCountStatus(testId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.reloadComponentsCount(testId);
  }

  async reloadComponentsCount(testId: string, silent = false): Promise<void> {
    const statusBefore = this.getComponentsCountStatus(testId);
    if (!silent) {
      this.componentsCountStatus.set(mapSetValue(this.componentsCountStatus(), testId, 'loading'));
    }
    try {
      const count = await this.api.getComponentsCount(testId);
      this.componentsCountState.set(mapSetValue(this.componentsCountState(), testId, count));
      this.componentsCountStatus.set(mapSetValue(this.componentsCountStatus(), testId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.componentsCountStatus.set(mapSetValue(this.componentsCountStatus(), testId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async ensureComponentsPreview(testId: string, limit: number): Promise<void> {
    const status = untracked(() => this.getComponentsStatus(testId));
    if (status === 'loading') {
      return;
    }
    // Preview data is already loaded for this test; avoid reloading on every reactive effect pass.
    if (status === 'loaded' && !untracked(() => this.getComponentsLoadedAll(testId))) {
      return;
    }
    await this.reloadComponentsPreview(testId, limit, status === 'loaded');
  }

  async reloadComponentsPreview(testId: string, limit: number, silent = false): Promise<void> {
    const statusBefore = this.getComponentsStatus(testId);
    if (!silent) {
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loading'));
    }
    if (this.getComponentsLoadedAll(testId)) {
      this.componentsLoadedAll.set(mapSetValue(this.componentsLoadedAll(), testId, false));
    }
    try {
      const items = await this.api.getComponentsPage(testId, 1, limit);
      this.componentsState.set(mapSetValue(this.componentsState(), testId, items));
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async reloadComponentsByQuery(testId: string, query: string, limit: number): Promise<void> {
    const q = query.trim();
    if (!q) {
      return;
    }
    this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loading'));
    this.componentsLoadedAll.set(mapSetValue(this.componentsLoadedAll(), testId, true));
    try {
      // Fetch first page only. The query narrows results and should remain small enough for in-memory filtering.
      const items = await this.api.getComponentsPage(testId, 1, Math.min(200, Math.max(1, limit)), q);
      this.componentsState.set(mapSetValue(this.componentsState(), testId, items));
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loaded'));
    } catch (error) {
      this.errorHandler.handleError(error);
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'error'));
    }
  }

  async ensureComponentsAll(testId: string): Promise<void> {
    const status = untracked(() => this.getComponentsStatus(testId));
    if (status === 'loading') {
      return;
    }
    await this.reloadComponentsAll(testId, status === 'loaded');
  }

  async reloadComponentsAll(testId: string, silent = false): Promise<void> {
    const statusBefore = this.getComponentsStatus(testId);
    if (!silent) {
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loading'));
    }
    try {
      const items = await this.api.getComponents(testId);
      this.componentsState.set(mapSetValue(this.componentsState(), testId, items));
      this.componentsLoadedAll.set(mapSetValue(this.componentsLoadedAll(), testId, true));
      this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.componentsStatus.set(mapSetValue(this.componentsStatus(), testId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async ensureComponents(testId: string): Promise<void> {
    await this.ensureComponentsAll(testId);
  }
}
