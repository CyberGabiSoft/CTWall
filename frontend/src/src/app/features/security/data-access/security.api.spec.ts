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
    expect(req.request.params.get('pageSize')).toBe('200');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('requests findings with full pagination', async () => {
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
    const page1 = http.expectOne((request) => request.url === '/api/v1/explorer/findings' && request.params.get('page') === '1');
    expect(page1.request.method).toBe('GET');
    expect(page1.request.params.get('sourceId')).toBe(sourceId);
    expect(page1.request.params.get('pageSize')).toBe('200');
    page1.flush({
      items: Array.from({ length: 200 }, (_, index) => ({
        id: `id-${index + 1}`,
        sourceId
      }))
    });

    await Promise.resolve();
    const page2 = http.expectOne((request) => request.url === '/api/v1/explorer/findings' && request.params.get('page') === '2');
    expect(page2.request.method).toBe('GET');
    expect(page2.request.params.get('sourceId')).toBe(sourceId);
    expect(page2.request.params.get('pageSize')).toBe('200');
    page2.flush({
      items: [
        { id: 'id-201', sourceId }
      ]
    });

    await expect(promise).resolves.toHaveLength(201);
    http.verify();
  });

  it('requests findings preview with capped pagination', async () => {
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

    const promise = api.listFindings(sourceId, { pageSize: 10, maxItems: 10 });
    const page1 = http.expectOne((request) => request.url === '/api/v1/explorer/findings' && request.params.get('page') === '1');
    expect(page1.request.method).toBe('GET');
    expect(page1.request.params.get('sourceId')).toBe(sourceId);
    expect(page1.request.params.get('pageSize')).toBe('10');
    page1.flush({
      items: Array.from({ length: 10 }, (_, index) => ({
        id: `id-${index + 1}`,
        sourceId
      }))
    });

    http.expectNone((request) => request.url === '/api/v1/explorer/findings' && request.params.get('page') === '2');
    await expect(promise).resolves.toHaveLength(10);
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
    expect(req.request.params.get('pageSize')).toBe('200');
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
    expect(req.request.params.get('pageSize')).toBe('200');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });
});
