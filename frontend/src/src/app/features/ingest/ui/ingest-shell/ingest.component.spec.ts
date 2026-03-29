import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { ActivatedRoute, convertToParamMap } from '@angular/router';
import { IngestComponent } from './ingest.component';
import { IngestApi } from '../../data-access/ingest.api';
import { IngestStore, LoadStatus } from '../../state/ingest.store';
import { AuthStore } from '../../../auth/auth.store';
import { of } from 'rxjs';

class IngestApiStub {
  async uploadSbom(): Promise<void> {}
  async getProducts(): Promise<void> {}
  async getScopes(): Promise<void> {}
  async getTests(): Promise<void> {}
}

class IngestStoreStub {
  readonly products = signal([]);
  readonly productsStatus = signal<LoadStatus>('loaded');
  readonly productsError = signal<string | null>(null);
  readonly scopes = signal([]);
  readonly scopesStatus = signal<LoadStatus>('idle');
  readonly scopesError = signal<string | null>(null);
  readonly tests = signal([]);
  readonly testsStatus = signal<LoadStatus>('idle');
  readonly testsError = signal<string | null>(null);

  async ensureProducts(): Promise<void> {}
  async loadProducts(): Promise<void> {}
  async ensureScopes(): Promise<void> {}
  async loadScopes(): Promise<void> {}
  async ensureTests(): Promise<void> {}
  async loadTests(): Promise<void> {}
  clearScopes(): void {}
  clearTests(): void {}
}

class AuthStoreStub {
  hasRole(): boolean {
    return true;
  }
}

describe('IngestComponent (TestBed)', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [IngestComponent],
      providers: [
        { provide: IngestApi, useClass: IngestApiStub },
        { provide: IngestStore, useClass: IngestStoreStub },
        { provide: AuthStore, useClass: AuthStoreStub },
        {
          provide: ActivatedRoute,
          useValue: {
            queryParamMap: of(convertToParamMap({}))
          }
        }
      ]
    }).compileComponents();
  });

  it('renders ingest form', () => {
    const fixture = TestBed.createComponent(IngestComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Import');
    expect(compiled.textContent).toContain('Product');
    expect(compiled.textContent).toContain('Scope');
    expect(compiled.textContent).toContain('Test mode');
    expect(compiled.textContent).toContain('Test name');
  });
});
