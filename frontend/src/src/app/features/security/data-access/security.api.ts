import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  MalwareSource,
  MalwareSourceUpdatePayload,
  MalwareSourceResultsRecomputeResponse,
  MalwareSummaryRecomputeResponse,
  RecomputeHistoryEntry,
  ScanComponentResult,
  SecurityPostureBucket,
  SecurityPostureOverviewResponse,
  SecurityPostureRange,
  SyncHistoryEntry,
  SyncStartResponse
} from './security.types';
import { extractItems } from '../../../shared/utils/api-payload';

@Injectable({ providedIn: 'root' })
export class SecurityApi {
  private readonly http = inject(HttpClient);

  async listSources(): Promise<MalwareSource[]> {
    return firstValueFrom(this.http.get<MalwareSource[]>('/explorer/sources'));
  }

  async updateSource(id: string, payload: MalwareSourceUpdatePayload): Promise<MalwareSource> {
    const encoded = encodeURIComponent(id);
    return firstValueFrom(this.http.patch<MalwareSource>(`/explorer/sources/${encoded}`, payload));
  }

  async triggerOsvFullSync(): Promise<SyncStartResponse> {
    return firstValueFrom(this.http.post<SyncStartResponse>('/explorer/osv/download_all', {}));
  }

  async triggerOsvLatestSync(): Promise<SyncStartResponse> {
    return firstValueFrom(this.http.post<SyncStartResponse>('/explorer/osv/download_latest', {}));
  }

  async recomputeAllActiveTestMalwareSummaries(): Promise<MalwareSummaryRecomputeResponse> {
    return firstValueFrom(
      this.http.post<MalwareSummaryRecomputeResponse>('/component-analysis/explorer/summary/recompute', {})
    );
  }

  async recomputeSourceResults(sourceId: string): Promise<MalwareSourceResultsRecomputeResponse> {
    const encoded = encodeURIComponent(sourceId);
    return firstValueFrom(
      this.http.post<MalwareSourceResultsRecomputeResponse>(`/explorer/sources/${encoded}/results/recompute`, {})
    );
  }

  async listFindings(sourceId?: string, page = 1, pageSize = 200): Promise<ScanComponentResult[]> {
    let params = new HttpParams()
      .set('page', String(page))
      .set('pageSize', String(pageSize));
    if (sourceId) {
      params = params.set('sourceId', sourceId);
    }
    const payload = await firstValueFrom(this.http.get<unknown>('/explorer/findings', { params }));
    return extractItems<ScanComponentResult>(payload);
  }

  async listSyncHistory(sourceId: string, pageSize = 50): Promise<SyncHistoryEntry[]> {
    const encoded = encodeURIComponent(sourceId);
    return this.fetchAll<SyncHistoryEntry>(`/explorer/sources/${encoded}/sync-history`, new HttpParams(), pageSize);
  }

  async listSyncErrors(sourceId: string, syncId: string, pageSize = 200): Promise<SyncHistoryEntry[]> {
    const source = encodeURIComponent(sourceId);
    const sync = encodeURIComponent(syncId);
    return this.fetchAll<SyncHistoryEntry>(
      `/explorer/sources/${source}/sync-history/${sync}/errors`,
      new HttpParams(),
      pageSize
    );
  }

  async listSourceResultsRecomputeHistory(sourceId: string, pageSize = 50): Promise<RecomputeHistoryEntry[]> {
    const encoded = encodeURIComponent(sourceId);
    return this.fetchAll<RecomputeHistoryEntry>(
      `/explorer/sources/${encoded}/results/recompute-history`,
      new HttpParams(),
      pageSize
    );
  }

  async listSummaryRecomputeHistory(pageSize = 50): Promise<RecomputeHistoryEntry[]> {
    return this.fetchAll<RecomputeHistoryEntry>(
      '/component-analysis/explorer/summary/recompute-history',
      new HttpParams(),
      pageSize
    );
  }

  async getPostureOverview(query: {
    range?: SecurityPostureRange;
    topN?: number;
    bucket?: SecurityPostureBucket;
  }): Promise<SecurityPostureOverviewResponse> {
    let params = new HttpParams();
    if (query.range) {
      params = params.set('range', query.range);
    }
    if (typeof query.topN === 'number') {
      params = params.set('topN', String(query.topN));
    }
    if (query.bucket) {
      params = params.set('bucket', query.bucket);
    }
    return firstValueFrom(
      this.http.get<SecurityPostureOverviewResponse>('/security/posture/overview', { params }),
    );
  }

  private async fetchAll<T>(url: string, params: HttpParams, pageSize = 200): Promise<T[]> {
    const normalizedPageSize = Math.max(1, pageSize);
    const items: T[] = [];
    let page = 1;

    while (true) {
      const pagedParams = params
        .set('page', String(page))
        .set('pageSize', String(normalizedPageSize));

      const payload = await firstValueFrom(this.http.get<unknown>(url, { params: pagedParams }));
      const batch = extractItems<T>(payload);
      items.push(...batch);

      if (batch.length < normalizedPageSize) {
        break;
      }

      page += 1;
    }

    return items;
  }
}
