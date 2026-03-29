import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ComponentAnalysisApi } from './component-analysis.api';
import { provideHttp } from '../../../core/providers/http';

describe('ComponentAnalysisApi (TestBed)', () => {
  it('requests malware schedule', async () => {
    await TestBed.configureTestingModule({
      providers: [
        ComponentAnalysisApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(ComponentAnalysisApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.getMalwareSchedule();
    const req = http.expectOne('/api/v1/component-analysis/explorer/schedule');
    expect(req.request.method).toBe('GET');
    req.flush({ enabled: true, interval: '24h0m0s', updatedAt: new Date().toISOString() });

    await expect(promise).resolves.toMatchObject({ enabled: true });
    http.verify();
  });

  it('patches malware schedule', async () => {
    await TestBed.configureTestingModule({
      providers: [
        ComponentAnalysisApi,
        ...provideHttp(),
        provideHttpClientTesting()
      ]
    }).compileComponents();

    const api = TestBed.inject(ComponentAnalysisApi);
    const http = TestBed.inject(HttpTestingController);

    const promise = api.updateMalwareSchedule({ enabled: false });
    const req = http.expectOne('/api/v1/component-analysis/explorer/schedule');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ enabled: false });
    req.flush({ enabled: false, interval: '24h0m0s', updatedAt: new Date().toISOString() });

    await expect(promise).resolves.toMatchObject({ enabled: false });
    http.verify();
  });
});
