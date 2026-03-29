import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SecurityApi } from './security.api';
import { provideHttp } from '../../../core/providers/http';

describe('SecurityApi (TestBed)', () => {
  it('requests malware sources', async () => {
    await TestBed.configureTestingModule({
      providers: [
        SecurityApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(SecurityApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.listSources();
    const req = http.expectOne('/api/v1/explorer/sources');
    expect(req.request.method).toBe('GET');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('requests sync history', async () => {
    await TestBed.configureTestingModule({
      providers: [
        SecurityApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(SecurityApi);
    const http = TestBed.inject(HttpTestingController);
    const sourceId = '0b40c0ef-7a91-4b40-8d40-2f8d8e93d7b8';

    const promise = api.listSyncHistory(sourceId);
    const req = http.expectOne((request) => request.url === `/api/v1/explorer/sources/${sourceId}/sync-history`);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('50');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('requests findings as a single paged call', async () => {
    await TestBed.configureTestingModule({
      providers: [
        SecurityApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(SecurityApi);
    const http = TestBed.inject(HttpTestingController);
    const sourceId = '0b40c0ef-7a91-4b40-8d40-2f8d8e93d7b8';

    const promise = api.listFindings(sourceId);
    const req = http.expectOne((request) => request.url === '/api/v1/explorer/findings');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('sourceId')).toBe(sourceId);
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('200');
    req.flush({ items: [] });

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('requests source results recompute history', async () => {
    await TestBed.configureTestingModule({
      providers: [
        SecurityApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(SecurityApi);
    const http = TestBed.inject(HttpTestingController);
    const sourceId = '0b40c0ef-7a91-4b40-8d40-2f8d8e93d7b8';

    const promise = api.listSourceResultsRecomputeHistory(sourceId);
    const req = http.expectOne((request) => request.url === `/api/v1/explorer/sources/${sourceId}/results/recompute-history`);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('50');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('requests summaries recompute history', async () => {
    await TestBed.configureTestingModule({
      providers: [
        SecurityApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(SecurityApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.listSummaryRecomputeHistory();
    const req = http.expectOne((request) => request.url === '/api/v1/component-analysis/explorer/summary/recompute-history');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('50');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });
});
