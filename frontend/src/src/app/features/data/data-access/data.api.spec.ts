import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { DataApi } from './data.api';
import { provideHttp } from '../../../core/providers/http';

describe('DataApi (TestBed)', () => {
  it('creates a product', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.createProduct('New Product');
    const req = http.expectOne('/api/v1/products');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ name: 'New Product' });
    req.flush({ id: 'p1', name: 'New Product' });

    await expect(promise).resolves.toEqual({ id: 'p1', name: 'New Product' });
    http.verify();
  });

  it('deletes a scope', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const scopeId = 's1';

    const deletePromise = api.deleteScope(scopeId);
    const deleteReq = http.expectOne('/api/v1/scopes/s1');
    expect(deleteReq.request.method).toBe('DELETE');
    deleteReq.flush(null);

    await expect(deletePromise).resolves.toBeUndefined();
    http.verify();
  });

  it('deletes a test', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const testId = 't1';

    const deletePromise = api.deleteTest(testId);
    const deleteReq = http.expectOne('/api/v1/tests/t1');
    expect(deleteReq.request.method).toBe('DELETE');
    deleteReq.flush(null);

    await expect(deletePromise).resolves.toBeUndefined();
    http.verify();
  });

  it('loads revision last changes with pagination', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getRevisionLastChanges('t1');
    const req = http.expectOne((request) => request.url === '/api/v1/tests/t1/revisions/last-changes');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('200');
    req.flush({
      items: [
        {
          toRevisionId: 'r1',
          projectId: 'p1',
          testId: 't1',
          addedCount: 1,
          removedCount: 0,
          unchangedCount: 4,
          reappearedCount: 0,
          status: 'COMPLETED'
        }
      ]
    });

    await expect(promise).resolves.toEqual([
      expect.objectContaining({
        toRevisionId: 'r1',
        status: 'COMPLETED'
      })
    ]);
    http.verify();
  });

  it('loads revision change summary for one revision', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getRevisionChangesSummary('t1', 'r1');
    const req = http.expectOne('/api/v1/tests/t1/revisions/r1/changes/summary');
    expect(req.request.method).toBe('GET');
    req.flush({
      toRevisionId: 'r1',
      projectId: 'p1',
      testId: 't1',
      addedCount: 1,
      removedCount: 2,
      unchangedCount: 3,
      reappearedCount: 0,
      status: 'COMPLETED'
    });

    await expect(promise).resolves.toEqual(
      expect.objectContaining({
        toRevisionId: 'r1',
        removedCount: 2
      })
    );
    http.verify();
  });

  it('loads product jira settings', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getProductJiraSettings('p1');
    const req = http.expectOne('/api/v1/data/products/p1/jira/settings');
    expect(req.request.method).toBe('GET');
    req.flush({
      id: 'j1',
      projectId: 'proj1',
      configLevel: 'PRODUCT',
      configTargetId: 'p1',
      isEnabled: false,
      jiraProjectKey: '',
      issueType: '',
      labels: [],
      components: [],
      severityToPriorityMapping: {},
      ticketSummaryTemplate: ''
    });

    await expect(promise).resolves.toEqual(
      expect.objectContaining({
        configLevel: 'PRODUCT',
        configTargetId: 'p1'
      })
    );
    http.verify();
  });

  it('requests jira metadata issue types with project key', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getJiraMetadataIssueTypes('APP', true);
    const req = http.expectOne((request) => request.url === '/api/v1/data/jira/metadata/issue-types');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('projectKey')).toBe('APP');
    expect(req.request.params.get('forceRefresh')).toBe('true');
    req.flush({
      fromCache: false,
      items: [{ id: '10001', name: 'Bug' }]
    });

    await expect(promise).resolves.toEqual({
      fromCache: false,
      items: [{ id: '10001', name: 'Bug' }]
    });
    http.verify();
  });

  it('requests jira metadata issues with project key', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getJiraMetadataIssues('KAN', true);
    const req = http.expectOne((request) => request.url === '/api/v1/data/jira/metadata/issues');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('projectKey')).toBe('KAN');
    expect(req.request.params.get('forceRefresh')).toBe('true');
    req.flush({
      fromCache: false,
      items: [{ id: '10011', key: 'KAN-11', summary: 'First issue', status: 'To Do' }]
    });

    await expect(promise).resolves.toEqual({
      fromCache: false,
      items: [{ id: '10011', key: 'KAN-11', summary: 'First issue', status: 'To Do' }]
    });
    http.verify();
  });

  it('requests jira metadata issues filtered by issue type name', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getJiraMetadataIssues('KAN', true, 'Epic');
    const req = http.expectOne((request) => request.url === '/api/v1/data/jira/metadata/issues');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('projectKey')).toBe('KAN');
    expect(req.request.params.get('forceRefresh')).toBe('true');
    expect(req.request.params.get('issueTypeName')).toBe('Epic');
    req.flush({
      fromCache: false,
      items: [{ id: '10021', key: 'KAN-21', summary: 'Security epic', status: 'To Do' }]
    });

    await expect(promise).resolves.toEqual({
      fromCache: false,
      items: [{ id: '10021', key: 'KAN-21', summary: 'Security epic', status: 'To Do' }]
    });
    http.verify();
  });

  it('requests jira metadata required issue fields by project and issue type id', async () => {
    await TestBed.configureTestingModule({
      providers: [DataApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(DataApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getJiraMetadataIssueFields('KAN', '10001', true);
    const req = http.expectOne((request) => request.url === '/api/v1/data/jira/metadata/issue-fields');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('projectKey')).toBe('KAN');
    expect(req.request.params.get('issueTypeId')).toBe('10001');
    expect(req.request.params.get('forceRefresh')).toBe('true');
    req.flush({
      fromCache: false,
      items: [{ key: 'customfield_10010', name: 'Environment', required: true, inputType: 'text', allowedValues: [] }]
    });

    await expect(promise).resolves.toEqual({
      fromCache: false,
      items: [{ key: 'customfield_10010', name: 'Environment', required: true, inputType: 'text', allowedValues: [] }]
    });
    http.verify();
  });
});
