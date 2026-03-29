import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  AlertDedupRule,
  AlertDedupRulesResponse,
  AlertGroupsListResponse,
  AlertOccurrencesListResponse,
  AlertSeverity,
  AlertingConnectorState,
  AlertingConnectorType,
  AlertingConnectorUpsertRequest,
  PutAlertDedupRulesRequest
} from './alerts.types';

export interface AlertGroupsListQuery {
  page: number;
  pageSize: number;
  severity?: AlertSeverity[];
  category?: string[];
  type?: string[];
  status?: Array<'OPEN' | 'ACKNOWLEDGED' | 'CLOSED'>;
  q?: string;
  from?: string;
  to?: string;
}

export interface AlertOccurrencesListQuery {
  page: number;
  pageSize: number;
  groupId?: string;
  severity?: AlertSeverity[];
  category?: string[];
  type?: string[];
  q?: string;
  from?: string;
  to?: string;
}

@Injectable({ providedIn: 'root' })
export class AlertsApi {
  private readonly http = inject(HttpClient);

  async listGroups(query: AlertGroupsListQuery): Promise<AlertGroupsListResponse> {
    let params = new HttpParams()
      .set('page', String(query.page))
      .set('pageSize', String(query.pageSize));

    const severity = query.severity ?? [];
    if (severity.length > 0) {
      params = params.set('severity', severity.join(','));
    }
    const category = (query.category ?? []).map((v) => v.trim()).filter(Boolean);
    if (category.length > 0) {
      params = params.set('category', category.join(','));
    }
    const type = (query.type ?? []).map((v) => v.trim()).filter(Boolean);
    if (type.length > 0) {
      params = params.set('type', type.join(','));
    }
    const status = (query.status ?? []).map((v) => v.trim()).filter(Boolean);
    if (status.length > 0) {
      params = params.set('status', status.join(','));
    }
    const q = (query.q ?? '').trim();
    if (q.length > 0) {
      params = params.set('q', q);
    }
    if ((query.from ?? '').trim()) {
      params = params.set('from', String(query.from));
    }
    if ((query.to ?? '').trim()) {
      params = params.set('to', String(query.to));
    }

    return firstValueFrom(this.http.get<AlertGroupsListResponse>('/alert-groups', { params }));
  }

  async acknowledgeGroup(id: string): Promise<void> {
    await firstValueFrom(this.http.post<void>(`/alert-groups/${encodeURIComponent(id)}/acknowledge`, {}));
  }

  async closeGroup(id: string): Promise<void> {
    await firstValueFrom(this.http.post<void>(`/alert-groups/${encodeURIComponent(id)}/close`, {}));
  }

  async listOccurrences(query: AlertOccurrencesListQuery): Promise<AlertOccurrencesListResponse> {
    let params = new HttpParams()
      .set('page', String(query.page))
      .set('pageSize', String(query.pageSize));

    const groupId = (query.groupId ?? '').trim();
    if (groupId) {
      params = params.set('groupId', groupId);
    }
    const severity = query.severity ?? [];
    if (severity.length > 0) {
      params = params.set('severity', severity.join(','));
    }
    const category = (query.category ?? []).map((v) => v.trim()).filter(Boolean);
    if (category.length > 0) {
      params = params.set('category', category.join(','));
    }
    const type = (query.type ?? []).map((v) => v.trim()).filter(Boolean);
    if (type.length > 0) {
      params = params.set('type', type.join(','));
    }
    const q = (query.q ?? '').trim();
    if (q.length > 0) {
      params = params.set('q', q);
    }
    if ((query.from ?? '').trim()) {
      params = params.set('from', String(query.from));
    }
    if ((query.to ?? '').trim()) {
      params = params.set('to', String(query.to));
    }

    return firstValueFrom(this.http.get<AlertOccurrencesListResponse>('/alert-occurrences', { params }));
  }

  async getAlertingConnectors(): Promise<AlertingConnectorState[]> {
    return firstValueFrom(this.http.get<AlertingConnectorState[]>('/alerting/connectors'));
  }

  async upsertAlertingConnector(type: AlertingConnectorType, payload: AlertingConnectorUpsertRequest): Promise<void> {
    await firstValueFrom(this.http.put<void>(`/alerting/connectors/${encodeURIComponent(type)}`, payload));
  }

  async listAlertDedupRules(alertType = 'malware.detected'): Promise<AlertDedupRule[]> {
    const params = new HttpParams().set('alertType', alertType);
    const response = await firstValueFrom(this.http.get<AlertDedupRulesResponse>('/alerting/dedup-rules', { params }));
    return response.items ?? [];
  }

  async putAlertDedupRules(payload: PutAlertDedupRulesRequest, alertType = 'malware.detected'): Promise<AlertDedupRule[]> {
    const params = new HttpParams().set('alertType', alertType);
    const response = await firstValueFrom(this.http.put<AlertDedupRulesResponse>('/alerting/dedup-rules', payload, { params }));
    return response.items ?? [];
  }
}
