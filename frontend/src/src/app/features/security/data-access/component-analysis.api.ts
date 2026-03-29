import { HttpClient, HttpContext, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  ComponentAnalysisFinding,
  ComponentAnalysisQueueItem,
  ComponentAnalysisReason,
  MalwareFindingPriority,
  MalwareFindingTriageStatus,
  MalwareRawFinding,
  MalwareResultSummary,
  TestRevisionMalwareSummary
} from './component-analysis.types';
import { extractItems } from '../../../shared/utils/api-payload';
import { SKIP_SUCCESS_FEEDBACK } from '../../../core/interceptors/success-feedback.interceptor';

export interface ComponentAnalysisQueueFilter {
  componentPurl?: string;
  status?: string;
  from?: string;
  to?: string;
  page?: number;
  pageSize?: number;
}

export interface ComponentAnalysisMalwareSchedule {
  enabled: boolean;
  interval: string;
  updatedAt: string;
}

export interface ComponentAnalysisMalwareSchedulePatchRequest {
  enabled?: boolean;
  interval?: string;
}

export interface MalwareFindingTriageUpsertPayload {
  componentPurl: string;
  malwarePurl: string;
  status: MalwareFindingTriageStatus;
  priority?: MalwareFindingPriority | null;
  reason?: string | null;
  expiresAt?: string | null; // RFC3339
}

export interface MalwareFindingTriageUpsertResponse {
  componentPurl: string;
  malwarePurl: string;
  status: MalwareFindingTriageStatus;
  priority?: MalwareFindingPriority | null;
  effectivePriority: MalwareFindingPriority;
  updatedAt: string;
}

@Injectable({ providedIn: 'root' })
export class ComponentAnalysisApi {
  private readonly http = inject(HttpClient);
  private readonly noSuccessFeedbackContext = new HttpContext().set(SKIP_SUCCESS_FEEDBACK, true);

  async enqueue(componentPurl: string, reason: ComponentAnalysisReason = 'MANUAL'): Promise<ComponentAnalysisQueueItem> {
    return firstValueFrom(
      this.http.post<ComponentAnalysisQueueItem>('/component-analysis/explorer/queue', {
        componentPurl,
        reason
      }, {
        context: this.noSuccessFeedbackContext
      })
    );
  }

  async listQueue(filter: ComponentAnalysisQueueFilter = {}): Promise<ComponentAnalysisQueueItem[]> {
    if (!filter.page && !filter.pageSize) {
      return this.fetchAllQueue(filter);
    }

    let params = new HttpParams();
    if (filter.componentPurl) {
      params = params.set('componentPurl', filter.componentPurl);
    }
    if (filter.status) {
      params = params.set('status', filter.status);
    }
    if (filter.from) {
      params = params.set('from', filter.from);
    }
    if (filter.to) {
      params = params.set('to', filter.to);
    }
    if (filter.page) {
      params = params.set('page', String(filter.page));
    }
    if (filter.pageSize) {
      params = params.set('pageSize', String(filter.pageSize));
    }
    const payload = await firstValueFrom(
      this.http.get<unknown>('/component-analysis/explorer/queue', { params })
    );
    return extractItems<ComponentAnalysisQueueItem>(payload);
  }

  async getQueueItem(runId: string): Promise<ComponentAnalysisQueueItem> {
    const encoded = encodeURIComponent(runId);
    return firstValueFrom(
      this.http.get<ComponentAnalysisQueueItem>(`/component-analysis/explorer/queue/${encoded}`)
    );
  }

  async listFindings(componentPurl: string): Promise<ComponentAnalysisFinding[]> {
    const params = new HttpParams().set('componentPurl', componentPurl);
    const payload = await firstValueFrom(
      this.http.get<unknown>('/component-analysis/explorer/findings', { params })
    );
    return extractItems<ComponentAnalysisFinding>(payload);
  }

  async listTestMalwareFindings(testId: string, page = 1, pageSize = 200): Promise<ComponentAnalysisFinding[]> {
    const encoded = encodeURIComponent(testId);
    const params = new HttpParams()
      .set('page', String(page))
      .set('pageSize', String(pageSize));
    const payload = await firstValueFrom(
      this.http.get<unknown>(`/tests/${encoded}/component-analysis/explorer/findings`, { params })
    );
    return extractItems<ComponentAnalysisFinding>(payload);
  }

  async listMalwareResults(purl?: string, page = 1, pageSize = 200): Promise<MalwareResultSummary[]> {
    let params = new HttpParams()
      .set('page', String(page))
      .set('pageSize', String(pageSize));
    if (purl) {
      params = params.set('purl', purl);
    }
    const payload = await firstValueFrom(this.http.get<unknown>('/explorer/results', { params }));
    return extractItems<MalwareResultSummary>(payload);
  }

  async listRawFindings(purl?: string, page = 1, pageSize = 200): Promise<MalwareRawFinding[]> {
    let params = new HttpParams()
      .set('page', String(page))
      .set('pageSize', String(pageSize));
    if (purl) {
      params = params.set('purl', purl);
    }
    const payload = await firstValueFrom(this.http.get<unknown>('/explorer/findings', { params }));
    return extractItems<MalwareRawFinding>(payload);
  }

  async getMalwareSchedule(): Promise<ComponentAnalysisMalwareSchedule> {
    return firstValueFrom(this.http.get<ComponentAnalysisMalwareSchedule>('/component-analysis/explorer/schedule'));
  }

  async updateMalwareSchedule(payload: ComponentAnalysisMalwareSchedulePatchRequest): Promise<ComponentAnalysisMalwareSchedule> {
    return firstValueFrom(this.http.patch<ComponentAnalysisMalwareSchedule>('/component-analysis/explorer/schedule', payload));
  }

  async getTestMalwareSummary(testId: string): Promise<TestRevisionMalwareSummary> {
    const encoded = encodeURIComponent(testId);
    return firstValueFrom(
      this.http.get<TestRevisionMalwareSummary>(`/tests/${encoded}/component-analysis/explorer/summary`)
    );
  }

  async upsertTestMalwareFindingTriage(testId: string, payload: MalwareFindingTriageUpsertPayload): Promise<MalwareFindingTriageUpsertResponse> {
    const encoded = encodeURIComponent(testId);
    return firstValueFrom(
      this.http.put<MalwareFindingTriageUpsertResponse>(`/tests/${encoded}/component-analysis/explorer/findings/triage`, payload)
    );
  }

  private async fetchAllQueue(filter: ComponentAnalysisQueueFilter): Promise<ComponentAnalysisQueueItem[]> {
    const pageSize = 200;
    const items: ComponentAnalysisQueueItem[] = [];
    let page = 1;

    while (true) {
      let params = new HttpParams()
        .set('page', String(page))
        .set('pageSize', String(pageSize));
      if (filter.componentPurl) {
        params = params.set('componentPurl', filter.componentPurl);
      }
      if (filter.status) {
        params = params.set('status', filter.status);
      }
      if (filter.from) {
        params = params.set('from', filter.from);
      }
      if (filter.to) {
        params = params.set('to', filter.to);
      }

      const payload = await firstValueFrom(
        this.http.get<unknown>('/component-analysis/explorer/queue', { params })
      );
      const batch = extractItems<ComponentAnalysisQueueItem>(payload);
      items.push(...batch);

      if (batch.length < pageSize) {
        break;
      }
      page += 1;
    }

    return items;
  }
}
