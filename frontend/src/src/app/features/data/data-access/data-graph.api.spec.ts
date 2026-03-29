import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttp } from '../../../core/providers/http';
import { DataGraphApi } from './data-graph.api';

describe('DataGraphApi (TestBed)', () => {
  it('requests dependency chain payload with query params', async () => {
    await TestBed.configureTestingModule({
      providers: [DataGraphApi, ...provideHttp(), provideHttpClientTesting()],
    }).compileComponents();

    const api = TestBed.inject(DataGraphApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getChain({
      testId: 't-1',
      revisionId: 'r-1',
      producer: 'syft',
      maxNodes: 1500,
    });
    const req = http.expectOne('/api/v1/data/graph/chain?testId=t-1&revisionId=r-1&producer=syft&maxNodes=1500');
    expect(req.request.method).toBe('GET');
    req.flush({
      scope: 'project',
      projectId: 'p-1',
      data: {
        nodes: [],
        edges: [],
        metadata: {
          projectId: 'p-1',
          productId: 'prd-1',
          productName: 'Product',
          scopeId: 'scp-1',
          scopeName: 'Scope',
          testId: 't-1',
          testName: 'Test',
          revisionId: 'r-1',
          sbomStandard: 'cyclonedx',
          sbomSpecVersion: '1.6',
          sbomProducer: 'syft',
          generatedAt: '2026-02-25T22:00:00Z',
          truncated: false,
          nodeCount: 0,
          edgeCount: 0,
        },
      },
    });

    await expect(promise).resolves.toEqual(
      expect.objectContaining({
        scope: 'project',
        projectId: 'p-1',
      }),
    );
    http.verify();
  });

  it('requests component details payload', async () => {
    await TestBed.configureTestingModule({
      providers: [DataGraphApi, ...provideHttp(), provideHttpClientTesting()],
    }).compileComponents();

    const api = TestBed.inject(DataGraphApi);
    const http = TestBed.inject(HttpTestingController);

    const purl = 'pkg:npm/acme-lib@1.2.3';
    const promise = api.getComponentDetails({
      testId: 't-1',
      revisionId: 'r-1',
      purl,
    });
    const req = http.expectOne(
      '/api/v1/data/graph/component-details?testId=t-1&purl=pkg:npm/acme-lib@1.2.3&revisionId=r-1',
    );
    expect(req.request.method).toBe('GET');
    req.flush({
      scope: 'project',
      projectId: 'p-1',
      testId: 't-1',
      revisionId: 'r-1',
      purl,
      data: {
        identity: {
          id: 'cmp-1',
          revisionId: 'r-1',
          purl,
          pkgName: 'acme-lib',
          version: '1.2.3',
          pkgType: 'npm',
          projectId: 'p-1',
          projectName: 'Project',
          productId: 'prd-1',
          productName: 'Product',
          scopeId: 'scp-1',
          scopeName: 'Scope',
          testId: 't-1',
          testName: 'Test',
          sbomStandard: 'cyclonedx',
          sbomSpecVersion: '1.6',
          sbomProducer: 'syft',
          revisionIsActive: true,
        },
        malwareSummary: {
          verdict: 'UNKNOWN',
          findingsCount: 0,
        },
        malwareFindings: [],
        rawFindings: [],
        queueHistory: [],
        occurrences: [],
      },
    });

    await expect(promise).resolves.toEqual(
      expect.objectContaining({
        purl,
      }),
    );
    http.verify();
  });
});

