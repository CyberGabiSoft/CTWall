import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import {
  DataGraphChainResponse,
  DataGraphComponentDetailsResponse,
  DataGraphProducer,
} from './data-graph.types';

export interface DataGraphChainQuery {
  testId: string;
  revisionId?: string;
  producer?: DataGraphProducer;
  maxNodes?: number;
}

export interface DataGraphComponentDetailsQuery {
  testId: string;
  revisionId?: string;
  purl: string;
}

@Injectable({ providedIn: 'root' })
export class DataGraphApi {
  private readonly http = inject(HttpClient);

  async getChain(query: DataGraphChainQuery): Promise<DataGraphChainResponse> {
    let params = new HttpParams().set('testId', query.testId);
    if (query.revisionId) {
      params = params.set('revisionId', query.revisionId);
    }
    if (query.producer) {
      params = params.set('producer', query.producer);
    }
    if (typeof query.maxNodes === 'number') {
      params = params.set('maxNodes', String(query.maxNodes));
    }
    return firstValueFrom(this.http.get<DataGraphChainResponse>('/data/graph/chain', { params }));
  }

  async getComponentDetails(
    query: DataGraphComponentDetailsQuery,
  ): Promise<DataGraphComponentDetailsResponse> {
    let params = new HttpParams().set('testId', query.testId).set('purl', query.purl);
    if (query.revisionId) {
      params = params.set('revisionId', query.revisionId);
    }
    return firstValueFrom(
      this.http.get<DataGraphComponentDetailsResponse>('/data/graph/component-details', {
        params,
      }),
    );
  }
}

