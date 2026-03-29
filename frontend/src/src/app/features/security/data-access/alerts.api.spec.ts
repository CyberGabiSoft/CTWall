import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideHttp } from '../../../core/providers/http';
import { AlertsApi } from './alerts.api';

describe('AlertsApi (TestBed)', () => {
  it('requests alert groups with pagination', async () => {
    await TestBed.configureTestingModule({
      providers: [AlertsApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(AlertsApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.listGroups({ page: 1, pageSize: 50, severity: ['ERROR'], status: ['OPEN'] });
    const req = http.expectOne((request) => request.url === '/api/v1/alert-groups');
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('pageSize')).toBe('50');
    expect(req.request.params.get('severity')).toBe('ERROR');
    expect(req.request.params.get('status')).toBe('OPEN');
    req.flush({ items: [], page: 1, pageSize: 50, total: 0, totalPages: 1 });

    await expect(promise).resolves.toEqual({ items: [], page: 1, pageSize: 50, total: 0, totalPages: 1 });
    http.verify();
  });

  it('requests alerting connectors', async () => {
    await TestBed.configureTestingModule({
      providers: [AlertsApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(AlertsApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getAlertingConnectors();
    const req = http.expectOne('/api/v1/alerting/connectors');
    expect(req.request.method).toBe('GET');
    req.flush([]);

    await expect(promise).resolves.toEqual([]);
    http.verify();
  });

  it('upserts jira alerting connector with dedup binding', async () => {
    await TestBed.configureTestingModule({
      providers: [AlertsApi, ...provideHttp(), provideHttpClientTesting()]
    }).compileComponents();

    const api = TestBed.inject(AlertsApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.upsertAlertingConnector('jira', {
      enabled: true,
      jiraDedupRuleId: 'dedup-1',
      routes: {
        productIds: ['p1'],
        scopeIds: ['s1'],
        testIds: ['t1']
      }
    });
    const req = http.expectOne('/api/v1/alerting/connectors/jira');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body.jiraDedupRuleId).toBe('dedup-1');
    expect(req.request.body.routes.productIds).toEqual(['p1']);
    req.flush(null);

    await expect(promise).resolves.toBeUndefined();
    http.verify();
  });
});
