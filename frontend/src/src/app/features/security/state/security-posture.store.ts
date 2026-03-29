import { ErrorHandler, Injectable, computed, inject, signal } from '@angular/core';
import { SecurityApi } from '../data-access/security.api';
import {
  SecurityPostureBucket,
  SecurityPostureOverviewData,
  SecurityPostureOverviewResponse,
  SecurityPostureRange,
} from '../data-access/security.types';

type LoadState = 'loading' | 'loaded' | 'error';
const ENSURE_COOLDOWN_MS = 1200;

const EMPTY_DATA: SecurityPostureOverviewData = {
  generatedAt: '',
  rangeStart: '',
  rangeEnd: '',
  projectId: '',
  topN: 5,
  bucket: 'day',
  score: {
    value: 100,
    label: '',
  },
  kpis: {
    totalProducts: 0,
    malwareProducts: 0,
    unknownPending: 0,
    activeComponents: 0,
    ingestFailures: 0,
    ingestCompleted: 0,
    ingestFailurePercent: 0,
    osvSyncStatus: 'UNKNOWN',
    osvLastSyncAt: null,
    osvErrors: 0,
    openErrorEvents: 0,
    queueBacklog: 0,
    inventoryTopType: '',
    lastAnalysisAt: null,
  },
  ingestTrend: [],
  ingestFailureTop: [],
  osvSyncTrend: [],
  osvTopErrorStages: [],
  inventoryTopTypesTotal: 0,
  inventoryTopTypes: [],
  recentUploads: [],
  recentFailures: [],
};

const EMPTY_RESPONSE: SecurityPostureOverviewResponse = {
  scope: 'project',
  projectId: '',
  range: '7d',
  bucket: 'day',
  data: EMPTY_DATA,
};

@Injectable({ providedIn: 'root' })
export class SecurityPostureStore {
  private readonly api = inject(SecurityApi);
  private readonly errorHandler = inject(ErrorHandler);
  private requestId = 0;
  private inFlightKey: string | null = null;
  private lastLoadedKey: string | null = null;
  private lastLoadedAt = 0;

  readonly status = signal<LoadState>('loading');
  readonly errorMessage = signal<string | null>(null);
  readonly range = signal<SecurityPostureRange>('7d');
  readonly topN = signal<number>(5);
  readonly bucket = signal<SecurityPostureBucket>('day');
  readonly response = signal<SecurityPostureOverviewResponse>(EMPTY_RESPONSE);

  readonly data = computed(() => this.response().data);
  readonly scope = computed(() => this.response().scope);

  private optionsKey(options: {
    range: SecurityPostureRange;
    topN: number;
    bucket: SecurityPostureBucket;
  }): string {
    return `${options.range}|${options.bucket}|${options.topN}`;
  }

  async ensureFresh(): Promise<void> {
    const options = {
      range: this.range(),
      topN: this.topN(),
      bucket: 'day' as SecurityPostureBucket,
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
        bucket: 'day' as SecurityPostureBucket,
      },
      false,
    );
  }

  async setRange(range: SecurityPostureRange): Promise<void> {
    if (this.range() === range) {
      return;
    }
    this.range.set(range);
    await this.reload();
  }

  async setBucket(bucket: SecurityPostureBucket): Promise<void> {
    if (bucket !== 'day' || this.bucket() === 'day') {
      return;
    }
    this.bucket.set('day');
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

  async load(options: {
    range: SecurityPostureRange;
    topN: number;
    bucket: SecurityPostureBucket;
  }, silent = false): Promise<void> {
    const activeRequest = ++this.requestId;
    const optionsKey = this.optionsKey(options);
    this.inFlightKey = optionsKey;
    const statusBefore = this.status();
    if (!silent) {
      this.status.set('loading');
      this.errorMessage.set(null);
    }
    try {
      const response = await this.api.getPostureOverview({
        range: options.range,
        topN: options.topN,
        bucket: options.bucket,
      });
      if (activeRequest !== this.requestId) {
        return;
      }
      this.response.set(response);
      this.range.set(response.range);
      this.topN.set(response.data.topN);
      this.bucket.set('day');
      this.status.set('loaded');
      this.lastLoadedKey = optionsKey;
      this.lastLoadedAt = Date.now();
    } catch (error: unknown) {
      if (activeRequest !== this.requestId) {
        return;
      }
      if (!silent) {
        this.status.set('error');
        this.errorMessage.set('Failed to load security posture overview.');
        this.errorHandler.handleError(error);
        return;
      }
      if (statusBefore === 'loading') {
        this.status.set('error');
        this.errorMessage.set('Failed to load security posture overview.');
        this.errorHandler.handleError(error);
      }
    } finally {
      if (activeRequest === this.requestId) {
        this.inFlightKey = null;
      }
    }
  }
}
