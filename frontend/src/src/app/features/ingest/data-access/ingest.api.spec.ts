import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttp } from '../../../core/providers/http';
import { IngestApi } from './ingest.api';

describe('IngestApi (TestBed)', () => {
  it('uploads an SBOM payload', async () => {
    await TestBed.configureTestingModule({
      providers: [IngestApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(IngestApi);
    const http = TestBed.inject(HttpTestingController);

    const file = new File(['{"bom":true}'], 'bom.json', { type: 'application/json' });

    const promise = api.uploadSbom({
      productId: 'p1',
      scopeId: 's1',
      testName: 'Test A',
      file
    });

    const req = http.expectOne('/api/v1/ingest');
    expect(req.request.method).toBe('POST');
    const body = req.request.body as FormData;
    expect(body.get('productId')).toBe('p1');
    expect(body.get('scopeId')).toBe('s1');
    expect(body.get('test')).toBe('Test A');
    expect(body.get('testId')).toBeNull();
    const uploadedFile = body.get('sbom_file') as File;
    expect(uploadedFile.name).toBe('bom.json');
    req.flush({
      productId: 'p1',
      scopeId: 's1',
      testId: 't1',
      revisionId: 'r1'
    });

    await expect(promise).resolves.toEqual({
      productId: 'p1',
      scopeId: 's1',
      testId: 't1',
      revisionId: 'r1'
    });
    http.verify();
  });

  it('uploads an SBOM payload for existing test', async () => {
    await TestBed.configureTestingModule({
      providers: [IngestApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(IngestApi);
    const http = TestBed.inject(HttpTestingController);

    const file = new File(['{"bom":true}'], 'bom.json', { type: 'application/json' });

    const promise = api.uploadSbom({
      productId: 'p1',
      scopeId: 's1',
      testId: 't-existing',
      file
    });

    const req = http.expectOne('/api/v1/ingest');
    expect(req.request.method).toBe('POST');
    const body = req.request.body as FormData;
    expect(body.get('productId')).toBe('p1');
    expect(body.get('scopeId')).toBe('s1');
    expect(body.get('testId')).toBe('t-existing');
    expect(body.get('test')).toBeNull();
    req.flush({
      productId: 'p1',
      scopeId: 's1',
      testId: 't-existing',
      revisionId: 'r1'
    });

    await expect(promise).resolves.toEqual({
      productId: 'p1',
      scopeId: 's1',
      testId: 't-existing',
      revisionId: 'r1'
    });
    http.verify();
  });
});
