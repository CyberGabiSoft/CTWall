import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { IngestProduct, IngestResponse, IngestScope, IngestTest } from './ingest.types';
import { extractItems } from '../../../shared/utils/api-payload';

@Injectable({ providedIn: 'root' })
export class IngestApi {
  private readonly http = inject(HttpClient);

  async getProducts(): Promise<IngestProduct[]> {
    return this.fetchAll<IngestProduct>('/products');
  }

  async getScopes(productId: string): Promise<IngestScope[]> {
    return this.fetchAll<IngestScope>(`/products/${encodeURIComponent(productId)}/scopes`);
  }

  async getTests(scopeId: string): Promise<IngestTest[]> {
    return this.fetchAll<IngestTest>(`/scopes/${encodeURIComponent(scopeId)}/tests`);
  }

  async uploadSbom(payload: {
    productId: string;
    scopeId: string;
    testName?: string;
    testId?: string;
    file: File;
  }): Promise<IngestResponse> {
    const form = new FormData();
    form.append('sbom_file', payload.file, payload.file.name);
    form.append('productId', payload.productId);
    form.append('scopeId', payload.scopeId);
    if (payload.testId?.trim()) {
      form.append('testId', payload.testId.trim());
    } else {
      form.append('test', (payload.testName ?? '').trim());
    }
    return firstValueFrom(this.http.post<IngestResponse>('/ingest', form));
  }

  private async fetchAll<T>(url: string): Promise<T[]> {
    const pageSize = 200;
    const items: T[] = [];
    let page = 1;

    while (true) {
      const params = new HttpParams()
        .set('page', String(page))
        .set('pageSize', String(pageSize));

      const payload = await firstValueFrom(this.http.get<unknown>(url, { params }));
      const batch = extractItems<T>(payload);
      items.push(...batch);

      if (batch.length < pageSize) {
        break;
      }

      page += 1;
    }

    return items;
  }
}
