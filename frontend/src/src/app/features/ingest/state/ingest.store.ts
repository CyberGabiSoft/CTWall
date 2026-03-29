import { ErrorHandler, Injectable, inject, signal, untracked } from '@angular/core';
import { IngestApi } from '../data-access/ingest.api';
import { IngestProduct, IngestScope, IngestTest } from '../data-access/ingest.types';

export type LoadStatus = 'idle' | 'loading' | 'loaded' | 'error';

@Injectable({ providedIn: 'root' })
export class IngestStore {
  private readonly api = inject(IngestApi);
  private readonly errorHandler = inject(ErrorHandler);

  readonly products = signal<IngestProduct[]>([]);
  readonly productsStatus = signal<LoadStatus>('idle');
  readonly productsError = signal<string | null>(null);

  readonly scopes = signal<IngestScope[]>([]);
  readonly scopesStatus = signal<LoadStatus>('idle');
  readonly scopesError = signal<string | null>(null);
  private lastScopeProductId: string | null = null;

  readonly tests = signal<IngestTest[]>([]);
  readonly testsStatus = signal<LoadStatus>('idle');
  readonly testsError = signal<string | null>(null);
  private lastTestScopeId: string | null = null;

  async ensureProducts(): Promise<void> {
    const status = untracked(() => this.productsStatus());
    if (status === 'loading') {
      return;
    }
    await this.loadProducts(status === 'loaded');
  }

  async loadProducts(silent = false): Promise<void> {
    const statusBefore = this.productsStatus();
    if (statusBefore === 'loading') {
      return;
    }
    if (!silent && statusBefore === 'loaded') {
      return;
    }
    if (!silent) {
      this.productsStatus.set('loading');
      this.productsError.set(null);
    }

    try {
      const products = await this.api.getProducts();
      this.products.set(products);
      this.productsStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.productsStatus.set('error');
        this.productsError.set('Unable to load products.');
        return;
      }
      if (statusBefore === 'idle') {
        this.errorHandler.handleError(error);
      }
    }
  }

  async ensureScopes(productId: string): Promise<void> {
    if (!productId) {
      return;
    }
    const status = untracked(() => this.scopesStatus());
    const sameProduct = this.lastScopeProductId === productId;
    if (status === 'loading' && sameProduct) {
      return;
    }
    await this.loadScopes(productId, status === 'loaded' && sameProduct);
  }

  async loadScopes(productId: string, silent = false): Promise<void> {
    if (!productId) {
      return;
    }
    const statusBefore = this.scopesStatus();
    const sameProduct = this.lastScopeProductId === productId;
    if (statusBefore === 'loading' && sameProduct) {
      return;
    }
    if (!silent && statusBefore === 'loaded' && sameProduct) {
      return;
    }
    if (!silent) {
      this.scopesStatus.set('loading');
      this.scopesError.set(null);
    }
    this.lastScopeProductId = productId;

    try {
      const scopes = await this.api.getScopes(productId);
      this.scopes.set(scopes);
      this.scopesStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.scopesStatus.set('error');
        this.scopesError.set('Unable to load scopes.');
        return;
      }
      if (statusBefore === 'idle') {
        this.errorHandler.handleError(error);
      }
    }
  }

  clearScopes(): void {
    this.scopes.set([]);
    this.scopesStatus.set('idle');
    this.scopesError.set(null);
    this.lastScopeProductId = null;
    this.clearTests();
  }

  async ensureTests(scopeId: string): Promise<void> {
    if (!scopeId) {
      return;
    }
    const status = untracked(() => this.testsStatus());
    const sameScope = this.lastTestScopeId === scopeId;
    if (status === 'loading' && sameScope) {
      return;
    }
    await this.loadTests(scopeId, status === 'loaded' && sameScope);
  }

  async loadTests(scopeId: string, silent = false): Promise<void> {
    if (!scopeId) {
      return;
    }
    const statusBefore = this.testsStatus();
    const sameScope = this.lastTestScopeId === scopeId;
    if (statusBefore === 'loading' && sameScope) {
      return;
    }
    if (!silent && statusBefore === 'loaded' && sameScope) {
      return;
    }
    if (!silent) {
      this.testsStatus.set('loading');
      this.testsError.set(null);
    }
    this.lastTestScopeId = scopeId;

    try {
      const tests = await this.api.getTests(scopeId);
      this.tests.set(tests);
      this.testsStatus.set('loaded');
    } catch (error) {
      if (!silent) {
        this.testsStatus.set('error');
        this.testsError.set('Unable to load tests.');
        return;
      }
      if (statusBefore === 'idle') {
        this.errorHandler.handleError(error);
      }
    }
  }

  clearTests(): void {
    this.tests.set([]);
    this.testsStatus.set('idle');
    this.testsError.set(null);
    this.lastTestScopeId = null;
  }
}
