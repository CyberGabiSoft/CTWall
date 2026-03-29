import { ErrorHandler, Injectable, computed, inject, signal } from '@angular/core';
import { DashboardApi } from '../data-access/dashboard.api';
import {
  DashboardOverviewData,
  DashboardOverviewResponse,
  DashboardRange,
} from '../data-access/dashboard.types';

type LoadState = 'loading' | 'loaded' | 'error';
const ENSURE_COOLDOWN_MS = 1200;

const EMPTY_DATA: DashboardOverviewData = {
  generatedAt: '',
  rangeStart: '',
  rangeEnd: '',
  projectCount: 0,
  topN: 5,
  kpis: {
    malwareActive: 0,
    affectedTests: 0,
    oldestPackageScanAt: null,
    lastAnalysisAt: null,
    lastMalwareSummaryComputedAt: null,
    ingestImports: 0,
    ingestComponents: 0,
    overridesActive: 0,
  },
  verdictDistribution: {
    malware: 0,
    clean: 0,
    unknown: 0,
  },
  topProductsTotal: 0,
  topScopesTotal: 0,
  topPackageTypesTotal: 0,
  topLicensesTotal: 0,
  topProducts: [],
  topScopes: [],
  topPackageTypes: [],
  topLicenses: [],
  topMalwarePackages: [],
  recentIngest: [],
  ingestTrend: [],
};

const EMPTY_RESPONSE: DashboardOverviewResponse = {
  scope: 'project',
  range: '7d',
  projectId: '',
  data: EMPTY_DATA,
};

@Injectable({ providedIn: 'root' })
export class DashboardStore {
  private readonly api = inject(DashboardApi);
  private readonly errorHandler = inject(ErrorHandler);
  private requestId = 0;
  private inFlightKey: string | null = null;
  private lastLoadedKey: string | null = null;
  private lastLoadedAt = 0;

  readonly status = signal<LoadState>('loading');
  readonly errorMessage = signal<string | null>(null);
  readonly range = signal<DashboardRange>('7d');
  readonly topN = signal<number>(5);
  readonly response = signal<DashboardOverviewResponse>(EMPTY_RESPONSE);

  readonly data = computed(() => this.response().data);
  readonly scope = computed(() => this.response().scope);

  private optionsKey(options: { range: DashboardRange; topN: number }): string {
    return `${options.range}|${options.topN}`;
  }

  async ensureFresh(): Promise<void> {
    const options = {
      range: this.range(),
      topN: this.topN(),
    };
    const key = this.optionsKey(options);
    const status = this.status();
    if (status === 'loading' && this.inFlightKey === key) {
      return;
    }
    if (
      status === 'loaded' &&
      this.lastLoadedKey === key &&
      Date.now() - this.lastLoadedAt < ENSURE_COOLDOWN_MS
    ) {
      return;
    }
    await this.load(options, status === 'loaded');
  }

  async reload(): Promise<void> {
    await this.load(
      {
        range: this.range(),
        topN: this.topN(),
      },
      false,
    );
  }

  async setRange(range: DashboardRange): Promise<void> {
    if (this.range() === range) {
      return;
    }
    this.range.set(range);
    await this.reload();
  }

  async setTopN(rawTopN: number): Promise<void> {
    const truncated = Number.isFinite(rawTopN) ? Math.trunc(rawTopN) : this.topN();
    if (truncated < 0) {
      return;
    }
    const normalized = truncated === 0 ? 0 : Math.max(1, truncated);
    if (this.topN() === normalized) {
      return;
    }
    this.topN.set(normalized);
    await this.reload();
  }

  async load(options: { range: DashboardRange; topN: number }, silent = false): Promise<void> {
    const activeRequest = ++this.requestId;
    const optionsKey = this.optionsKey(options);
    this.inFlightKey = optionsKey;
    const statusBefore = this.status();
    if (!silent) {
      this.status.set('loading');
      this.errorMessage.set(null);
    }
    try {
      const response = await this.api.getOverview({
        range: options.range,
        topN: options.topN,
      });
      if (activeRequest !== this.requestId) {
        return;
      }
      this.response.set(response);
      this.range.set(response.range);
      this.topN.set(response.data.topN);
      this.status.set('loaded');
      this.lastLoadedKey = optionsKey;
      this.lastLoadedAt = Date.now();
    } catch (error: unknown) {
      if (activeRequest !== this.requestId) {
        return;
      }
      if (!silent) {
        this.status.set('error');
        this.errorMessage.set('Failed to load dashboard overview.');
        this.errorHandler.handleError(error);
        return;
      }
      if (statusBefore === 'loading') {
        this.status.set('error');
        this.errorMessage.set('Failed to load dashboard overview.');
        this.errorHandler.handleError(error);
      }
    } finally {
      if (activeRequest === this.requestId) {
        this.inFlightKey = null;
      }
    }
  }
}
