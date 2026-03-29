import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ComponentOccurrenceResponse } from './search.types';

@Injectable({ providedIn: 'root' })
export class SearchApi {
  private readonly http = inject(HttpClient);

  async searchComponentOccurrences(q: string, page: number, pageSize: number): Promise<ComponentOccurrenceResponse> {
    const params = new HttpParams()
      .set('q', q)
      .set('page', String(page))
      .set('pageSize', String(pageSize));

    return firstValueFrom(
      this.http.get<ComponentOccurrenceResponse>('/search/component-occurrences', { params })
    );
  }
}

