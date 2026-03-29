import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { DashboardOverviewResponse, DashboardRange } from './dashboard.types';

export interface DashboardOverviewQuery {
  range?: DashboardRange;
  topN?: number;
}

@Injectable({ providedIn: 'root' })
export class DashboardApi {
  private readonly http = inject(HttpClient);

  async getOverview(query: DashboardOverviewQuery): Promise<DashboardOverviewResponse> {
    let params = new HttpParams();
    if (query.range) {
      params = params.set('range', query.range);
    }
    if (typeof query.topN === 'number') {
      params = params.set('topN', String(query.topN));
    }
    return firstValueFrom(
      this.http.get<DashboardOverviewResponse>('/dashboard/overview', { params }),
    );
  }
}
