import { ErrorHandler, Injectable, computed, inject, signal, untracked } from '@angular/core';
import { SecurityApi } from '../data-access/security.api';
import {
  MalwareSource,
  MalwareSourceResultsRecomputeResponse,
  MalwareSummaryRecomputeResponse,
  RecomputeHistoryEntry,
  ScanComponentResult,
  SyncHistoryEntry,
  SyncStartResponse
} from '../data-access/security.types';
import { mapGetValue, mapSetValue } from '../../../shared/utils/map-utils';
import { LoadState } from '../../../shared/types/load-state';

export type { LoadState } from '../../../shared/types/load-state';

@Injectable({ providedIn: 'root' })
export class SecurityStore {
  private readonly sourcesState = signal<MalwareSource[]>([]);
  private readonly sourcesStatus = signal<LoadState>('idle');

  private readonly findingsState = signal<Map<string, ScanComponentResult[]>>(new Map());
  private readonly findingsStatus = signal<Map<string, LoadState>>(new Map());

  private readonly syncHistoryState = signal<Map<string, SyncHistoryEntry[]>>(new Map());
  private readonly syncHistoryStatus = signal<Map<string, LoadState>>(new Map());

  private readonly sourceResultsRecomputeHistoryState = signal<Map<string, RecomputeHistoryEntry[]>>(new Map());
  private readonly sourceResultsRecomputeHistoryStatus = signal<Map<string, LoadState>>(new Map());

  private readonly summaryRecomputeHistoryState = signal<RecomputeHistoryEntry[]>([]);
  private readonly summaryRecomputeHistoryStatus = signal<LoadState>('idle');

  private readonly lastSyncState = signal<SyncStartResponse | null>(null);
  private readonly summaryRecomputeStatus = signal<LoadState>('idle');
  private readonly lastSummaryRecomputeState = signal<MalwareSummaryRecomputeResponse | null>(null);
  private readonly sourceResultsRecomputeStatus = signal<Map<string, LoadState>>(new Map());

  readonly sources = computed(() => this.sourcesState());
  readonly sourcesLoadState = computed(() => this.sourcesStatus());
  readonly lastSync = computed(() => this.lastSyncState());
  readonly summaryRecomputeLoadState = computed(() => this.summaryRecomputeStatus());
  readonly lastSummaryRecompute = computed(() => this.lastSummaryRecomputeState());

  private readonly api = inject(SecurityApi);
  private readonly errorHandler = inject(ErrorHandler);

  private handleSilentLoadError(statusBefore: LoadState, error: unknown): void {
    if (statusBefore === 'idle') {
      this.errorHandler.handleError(error);
    }
  }

  async ensureSources(): Promise<void> {
    const status = untracked(() => this.sourcesStatus());
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.refreshSources();
  }

  async refreshSources(silent = false): Promise<void> {
    const statusBefore = this.sourcesStatus();
    if (!silent) {
      this.sourcesStatus.set('loading');
    }

    try {
      const items = await this.api.listSources();
      this.sourcesState.set(items);
      this.sourcesStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.sourcesStatus.set('error');
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  getSourceById(sourceId: string): MalwareSource | undefined {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return undefined;
    }
    return this.sourcesState().find((source) => source.id === normalizedSourceId);
  }

  getFindings(sourceId: string): ScanComponentResult[] {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return [];
    }
    return mapGetValue(this.findingsState(), normalizedSourceId) ?? [];
  }

  getFindingsStatus(sourceId: string): LoadState {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return 'idle';
    }
    return mapGetValue(this.findingsStatus(), normalizedSourceId) ?? 'idle';
  }

  getSyncHistory(sourceId: string): SyncHistoryEntry[] {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return [];
    }
    return mapGetValue(this.syncHistoryState(), normalizedSourceId) ?? [];
  }

  getSyncHistoryStatus(sourceId: string): LoadState {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return 'idle';
    }
    return mapGetValue(this.syncHistoryStatus(), normalizedSourceId) ?? 'idle';
  }

  getSourceResultsRecomputeHistory(sourceId: string): RecomputeHistoryEntry[] {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return [];
    }
    return mapGetValue(this.sourceResultsRecomputeHistoryState(), normalizedSourceId) ?? [];
  }

  getSourceResultsRecomputeHistoryStatus(sourceId: string): LoadState {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return 'idle';
    }
    return mapGetValue(this.sourceResultsRecomputeHistoryStatus(), normalizedSourceId) ?? 'idle';
  }

  getSummaryRecomputeHistory(): RecomputeHistoryEntry[] {
    return this.summaryRecomputeHistoryState();
  }

  getSummaryRecomputeHistoryStatus(): LoadState {
    return this.summaryRecomputeHistoryStatus();
  }

  getSourceResultsRecomputeStatus(sourceId: string): LoadState {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return 'idle';
    }
    return mapGetValue(this.sourceResultsRecomputeStatus(), normalizedSourceId) ?? 'idle';
  }

  async ensureFindings(sourceId: string): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const status = untracked(() => this.getFindingsStatus(normalizedSourceId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.refreshFindings(normalizedSourceId);
  }

  async refreshFindings(sourceId: string, silent = false): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const statusBefore = this.getFindingsStatus(normalizedSourceId);
    if (!silent) {
      this.findingsStatus.set(mapSetValue(this.findingsStatus(), normalizedSourceId, 'loading'));
    }

    try {
      const items = await this.api.listFindings(normalizedSourceId);
      this.findingsState.set(mapSetValue(this.findingsState(), normalizedSourceId, items));
      this.findingsStatus.set(mapSetValue(this.findingsStatus(), normalizedSourceId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.findingsStatus.set(mapSetValue(this.findingsStatus(), normalizedSourceId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async ensureSyncHistory(sourceId: string): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const status = untracked(() => this.getSyncHistoryStatus(normalizedSourceId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.refreshSyncHistory(normalizedSourceId);
  }

  async refreshSyncHistory(sourceId: string, silent = false): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const statusBefore = this.getSyncHistoryStatus(normalizedSourceId);
    if (!silent) {
      this.syncHistoryStatus.set(mapSetValue(this.syncHistoryStatus(), normalizedSourceId, 'loading'));
    }

    try {
      const items = await this.api.listSyncHistory(normalizedSourceId);
      this.syncHistoryState.set(mapSetValue(this.syncHistoryState(), normalizedSourceId, items));
      this.syncHistoryStatus.set(mapSetValue(this.syncHistoryStatus(), normalizedSourceId, 'loaded'));
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.syncHistoryStatus.set(mapSetValue(this.syncHistoryStatus(), normalizedSourceId, 'error'));
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  // Background refresh that does not flip the UI into a "loading" state.
  // Intended for polling while a sync is running to avoid table flicker.
  async refreshSyncHistorySilent(sourceId: string): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const previous = this.getSyncHistoryStatus(normalizedSourceId);

    try {
      const items = await this.api.listSyncHistory(normalizedSourceId);
      this.syncHistoryState.set(mapSetValue(this.syncHistoryState(), normalizedSourceId, items));
      this.syncHistoryStatus.set(mapSetValue(this.syncHistoryStatus(), normalizedSourceId, 'loaded'));
    } catch (error) {
      // Avoid spamming global error handling for background polling.
      // Keep last known good data and status when possible.
      if (previous === 'idle') {
        this.errorHandler.handleError(error);
        this.syncHistoryStatus.set(mapSetValue(this.syncHistoryStatus(), normalizedSourceId, 'error'));
      }
    }
  }

  async ensureSourceResultsRecomputeHistory(sourceId: string): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const status = untracked(() => this.getSourceResultsRecomputeHistoryStatus(normalizedSourceId));
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.refreshSourceResultsRecomputeHistory(normalizedSourceId);
  }

  async refreshSourceResultsRecomputeHistory(sourceId: string, silent = false): Promise<void> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return;
    }
    const statusBefore = this.getSourceResultsRecomputeHistoryStatus(normalizedSourceId);
    if (!silent) {
      this.sourceResultsRecomputeHistoryStatus.set(
        mapSetValue(this.sourceResultsRecomputeHistoryStatus(), normalizedSourceId, 'loading'),
      );
    }

    try {
      const items = await this.api.listSourceResultsRecomputeHistory(normalizedSourceId);
      this.sourceResultsRecomputeHistoryState.set(
        mapSetValue(this.sourceResultsRecomputeHistoryState(), normalizedSourceId, items)
      );
      this.sourceResultsRecomputeHistoryStatus.set(
        mapSetValue(this.sourceResultsRecomputeHistoryStatus(), normalizedSourceId, 'loaded')
      );
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.sourceResultsRecomputeHistoryStatus.set(
          mapSetValue(this.sourceResultsRecomputeHistoryStatus(), normalizedSourceId, 'error'),
        );
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async ensureSummaryRecomputeHistory(): Promise<void> {
    const status = untracked(() => this.summaryRecomputeHistoryStatus());
    if (status === 'loading' || status === 'loaded') {
      return;
    }
    await this.refreshSummaryRecomputeHistory();
  }

  async refreshSummaryRecomputeHistory(silent = false): Promise<void> {
    const statusBefore = this.summaryRecomputeHistoryStatus();
    if (!silent) {
      this.summaryRecomputeHistoryStatus.set('loading');
    }

    try {
      const items = await this.api.listSummaryRecomputeHistory();
      this.summaryRecomputeHistoryState.set(items);
      this.summaryRecomputeHistoryStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.errorHandler.handleError(error);
        this.summaryRecomputeHistoryStatus.set('error');
        return;
      }
      this.handleSilentLoadError(statusBefore, error);
    }
  }

  async updateSource(sourceId: string, payload: { isActive?: boolean; baseUrl?: string; config?: Record<string, string> }): Promise<void> {
    try {
      const updated = await this.api.updateSource(sourceId, payload);
      const sources = this.sourcesState();
      const next = sources.map((source) => (source.id === updated.id ? updated : source));
      this.sourcesState.set(next);
    } catch (error) {
      this.errorHandler.handleError(error);
    }
  }

  async triggerFullSync(): Promise<SyncStartResponse | null> {
    try {
      const result = await this.api.triggerOsvFullSync();
      this.lastSyncState.set(result);
      return result;
    } catch (error) {
      this.errorHandler.handleError(error);
      return null;
    }
  }

  async triggerLatestSync(): Promise<SyncStartResponse | null> {
    try {
      const result = await this.api.triggerOsvLatestSync();
      this.lastSyncState.set(result);
      return result;
    } catch (error) {
      this.errorHandler.handleError(error);
      return null;
    }
  }

  async recomputeAllActiveTestMalwareSummaries(): Promise<MalwareSummaryRecomputeResponse | null> {
    if (this.summaryRecomputeStatus() === 'loading') {
      return null;
    }
    this.summaryRecomputeStatus.set('loading');
    try {
      const result = await this.api.recomputeAllActiveTestMalwareSummaries();
      this.lastSummaryRecomputeState.set(result);
      this.summaryRecomputeStatus.set('loaded');
      return result;
    } catch (error) {
      this.errorHandler.handleError(error);
      this.summaryRecomputeStatus.set('error');
      return null;
    }
  }

  async recomputeSourceResults(sourceId: string): Promise<MalwareSourceResultsRecomputeResponse | null> {
    const normalizedSourceId = sourceId.trim();
    if (!normalizedSourceId) {
      return null;
    }
    if (this.getSourceResultsRecomputeStatus(normalizedSourceId) === 'loading') {
      return null;
    }
    this.sourceResultsRecomputeStatus.set(
      mapSetValue(this.sourceResultsRecomputeStatus(), normalizedSourceId, 'loading')
    );
    try {
      const result = await this.api.recomputeSourceResults(normalizedSourceId);
      this.sourceResultsRecomputeStatus.set(
        mapSetValue(this.sourceResultsRecomputeStatus(), normalizedSourceId, 'loaded')
      );
      return result;
    } catch (error) {
      this.errorHandler.handleError(error);
      this.sourceResultsRecomputeStatus.set(
        mapSetValue(this.sourceResultsRecomputeStatus(), normalizedSourceId, 'error')
      );
      return null;
    }
  }
}
