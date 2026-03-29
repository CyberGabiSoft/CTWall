import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  EventDetailsResponse,
  EventsListResponse,
  EventsOpenCountResponse
} from './events.types';

export interface EventsListQuery {
  severities?: Array<'INFO' | 'WARN' | 'ERROR'>;
  // Category filters aligned per severity. Empty/omitted means "all categories" for that severity.
  categoriesError?: string[];
  categoriesWarn?: string[];
  categoriesInfo?: string[];
  status?: 'open' | 'acknowledged';
  q?: string;
  page?: number;
  pageSize?: number;
}

@Injectable({ providedIn: 'root' })
export class EventsApi {
  private readonly http = inject(HttpClient);

  async openCount(): Promise<EventsOpenCountResponse> {
    return firstValueFrom(this.http.get<EventsOpenCountResponse>('/events/open-count'));
  }

  async list(query: EventsListQuery): Promise<EventsListResponse> {
    let params = new HttpParams();
    const severities = query.severities ?? [];
    if (severities.length > 0) {
      params = params.set('severity', severities.join(','));
    }
    const categoriesError = query.categoriesError ?? [];
    if (categoriesError.length > 0) {
      params = params.set('category_in_error', categoriesError.join(','));
    }
    const categoriesWarn = query.categoriesWarn ?? [];
    if (categoriesWarn.length > 0) {
      params = params.set('category_in_warn', categoriesWarn.join(','));
    }
    const categoriesInfo = query.categoriesInfo ?? [];
    if (categoriesInfo.length > 0) {
      params = params.set('category_in_info', categoriesInfo.join(','));
    }
    if (query.status) {
      params = params.set('status', query.status);
    }
    if (query.q) {
      params = params.set('q', query.q);
    }
    if (typeof query.page === 'number') {
      params = params.set('page', String(query.page));
    }
    if (typeof query.pageSize === 'number') {
      params = params.set('pageSize', String(query.pageSize));
    }
    return firstValueFrom(this.http.get<EventsListResponse>('/events', { params }));
  }

  async get(eventKey: string): Promise<EventDetailsResponse> {
    const encoded = encodeURIComponent(eventKey);
    return firstValueFrom(this.http.get<EventDetailsResponse>(`/events/${encoded}`));
  }

  async ack(eventKey: string): Promise<void> {
    const encoded = encodeURIComponent(eventKey);
    await firstValueFrom(this.http.post<void>(`/events/${encoded}/ack`, {}));
  }
}
