import { ErrorHandler, Injectable, computed, inject, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { DataApi } from '../data-access/data.api';
import { ProductSummary, ScopeSummary, TestRevisionSummary, TestSummary } from '../data-access/data.types';
import { DataGraphApi } from '../data-access/data-graph.api';
import {
  DataGraphChainResponse,
  DataGraphComponentDetailsData,
  DataGraphNode,
  DataGraphProducer,
} from '../data-access/data-graph.types';
import { LoadState } from '../../../shared/types/load-state';


const EMPTY_CHAIN: DataGraphChainResponse = {
  scope: 'project',
  projectId: '',
  data: {
    nodes: [],
    edges: [],
    metadata: {
      projectId: '',
      productId: '',
      productName: '',
      scopeId: '',
      scopeName: '',
      testId: '',
      testName: '',
      revisionId: '',
      sbomStandard: '',
      sbomSpecVersion: '',
      sbomProducer: '',
      generatedAt: '',
      truncated: false,
      nodeCount: 0,
      edgeCount: 0,
    },
  },
};

@Injectable({ providedIn: 'root' })
export class DataGraphStore {
  private readonly dataApi = inject(DataApi);
  private readonly graphApi = inject(DataGraphApi);
  private readonly errorHandler = inject(ErrorHandler);

  private initStarted = false;
  private graphRequestId = 0;
  private detailsRequestId = 0;

  readonly controlsStatus = signal<LoadState>('idle');
  readonly controlsError = signal<string | null>(null);

  readonly graphStatus = signal<LoadState>('idle');
  readonly graphError = signal<string | null>(null);
  readonly chainResponse = signal<DataGraphChainResponse>(EMPTY_CHAIN);

  readonly detailsStatus = signal<LoadState>('idle');
  readonly detailsError = signal<string | null>(null);
  readonly detailsByPurl = signal<Map<string, DataGraphComponentDetailsData>>(new Map());

  readonly products = signal<ProductSummary[]>([]);
  readonly scopes = signal<ScopeSummary[]>([]);
  readonly tests = signal<TestSummary[]>([]);
  readonly revisions = signal<TestRevisionSummary[]>([]);

  readonly selectedProductId = signal<string | null>(null);
  readonly selectedScopeId = signal<string | null>(null);
  readonly selectedTestId = signal<string | null>(null);
  readonly selectedProducer = signal<DataGraphProducer | ''>('');
  readonly selectedRevisionId = signal<string>('');
  readonly maxNodes = signal<number>(1200);
  readonly selectedNodeId = signal<string | null>(null);

  readonly selectedProduct = computed(() =>
    this.findById(this.products(), this.selectedProductId()),
  );
  readonly selectedScope = computed(() => this.findById(this.scopes(), this.selectedScopeId()));
  readonly selectedTest = computed(() => this.findById(this.tests(), this.selectedTestId()));
  readonly selectedRevision = computed(() => this.findById(this.revisions(), this.selectedRevisionId()));

  readonly graphNodes = computed(() => this.chainResponse().data.nodes);
  readonly graphEdges = computed(() => this.chainResponse().data.edges);
  readonly graphMetadata = computed(() => this.chainResponse().data.metadata);
  readonly hasGraph = computed(() => this.graphNodes().length > 0);

  readonly selectedNode = computed<DataGraphNode | null>(() => {
    const nodeId = this.selectedNodeId();
    if (!nodeId) {
      return null;
    }
    return this.graphNodes().find((item) => item.id === nodeId) ?? null;
  });

  readonly selectedDetails = computed<DataGraphComponentDetailsData | null>(() => {
    const node = this.selectedNode();
    if (!node) {
      return null;
    }
    return this.detailsByPurl().get(node.purl) ?? null;
  });

  async initialize(): Promise<void> {
    if (this.initStarted) {
      await this.loadProducts(true);
      return;
    }
    this.initStarted = true;
    await this.loadProducts(false);
  }

  async setProductId(productId: string | null): Promise<void> {
    if (this.selectedProductId() === productId) {
      return;
    }
    this.selectedProductId.set(productId);
    this.selectedScopeId.set(null);
    this.selectedTestId.set(null);
    this.selectedRevisionId.set('');
    this.scopes.set([]);
    this.tests.set([]);
    this.revisions.set([]);
    this.resetGraphState();
    await this.loadScopes();
  }

  async setScopeId(scopeId: string | null): Promise<void> {
    if (this.selectedScopeId() === scopeId) {
      return;
    }
    this.selectedScopeId.set(scopeId);
    this.selectedTestId.set(null);
    this.selectedRevisionId.set('');
    this.tests.set([]);
    this.revisions.set([]);
    this.resetGraphState();
    await this.loadTests();
  }

  async setTestId(testId: string | null): Promise<void> {
    if (this.selectedTestId() === testId) {
      return;
    }
    this.selectedTestId.set(testId);
    this.selectedRevisionId.set('');
    this.revisions.set([]);
    this.resetGraphState();
    await this.loadRevisions();
  }

  setProducer(producer: DataGraphProducer | ''): void {
    this.selectedProducer.set(producer);
  }

  setRevisionId(revisionId: string): void {
    this.selectedRevisionId.set(revisionId.trim());
  }

  setMaxNodes(value: number): void {
    const normalized = Math.max(1, Math.min(5000, Math.trunc(value)));
    this.maxNodes.set(normalized);
  }

  async renderGraph(): Promise<boolean> {
    const testId = this.selectedTestId();
    if (!testId) {
      return false;
    }
    const requestedRevisionID = this.selectedRevisionId().trim();
    const requestedProducer = this.selectedProducer() || undefined;
    const requestedMaxNodes = this.maxNodes();

    const requestId = ++this.graphRequestId;
    this.graphStatus.set('loading');
    this.graphError.set(null);
    this.selectedNodeId.set(null);
    this.detailsStatus.set('idle');
    this.detailsError.set(null);
    this.detailsByPurl.set(new Map());

    try {
      const response = await this.graphApi.getChain({
        testId,
        revisionId: requestedRevisionID || undefined,
        producer: requestedProducer,
        maxNodes: requestedMaxNodes,
      });
      if (requestId !== this.graphRequestId) {
        return false;
      }
      this.chainResponse.set(response);
      this.graphStatus.set('loaded');
      return true;
    } catch (error: unknown) {
      if (
        requestedRevisionID &&
        this.resolveHttpStatus(error) === 404
      ) {
        try {
          const fallback = await this.graphApi.getChain({
            testId,
            producer: requestedProducer,
            maxNodes: requestedMaxNodes,
          });
          if (requestId !== this.graphRequestId) {
            return false;
          }
          this.chainResponse.set(fallback);
          this.selectedRevisionId.set('');
          this.graphStatus.set('loaded');
          return true;
        } catch (fallbackError: unknown) {
          if (requestId !== this.graphRequestId) {
            return false;
          }
          this.graphStatus.set('error');
          this.graphError.set(
            this.resolveProblemDetail(fallbackError, 'Failed to render dependency graph.'),
          );
          this.handleUnexpectedError(fallbackError);
          return false;
        }
      }
      if (requestId !== this.graphRequestId) {
        return false;
      }
      this.graphStatus.set('error');
      this.graphError.set(this.resolveProblemDetail(error, 'Failed to render dependency graph.'));
      this.handleUnexpectedError(error);
      return false;
    }
  }

  async selectNode(nodeId: string): Promise<void> {
    this.selectedNodeId.set(nodeId);
    const node = this.selectedNode();
    if (!node) {
      return;
    }

    const cached = this.detailsByPurl().get(node.purl);
    if (cached) {
      this.detailsStatus.set('loaded');
      this.detailsError.set(null);
      return;
    }

    const testId = this.selectedTestId();
    const revisionId = this.graphMetadata().revisionId;
    if (!testId || !revisionId) {
      return;
    }

    const requestId = ++this.detailsRequestId;
    this.detailsStatus.set('loading');
    this.detailsError.set(null);
    try {
      const response = await this.graphApi.getComponentDetails({
        testId,
        revisionId,
        purl: node.purl,
      });
      if (requestId !== this.detailsRequestId) {
        return;
      }
      this.detailsByPurl.update((current) => {
        const next = new Map(current);
        next.set(node.purl, response.data);
        return next;
      });
      this.detailsStatus.set('loaded');
    } catch (error: unknown) {
      if (requestId !== this.detailsRequestId) {
        return;
      }
      this.detailsStatus.set('error');
      this.detailsError.set(
        this.resolveProblemDetail(error, 'Failed to load selected component details.'),
      );
      this.handleUnexpectedError(error);
    }
  }

  private async loadProducts(silent: boolean): Promise<void> {
    const statusBefore = this.controlsStatus();
    if (!silent) {
      this.controlsStatus.set('loading');
      this.controlsError.set(null);
    }
    try {
      const products = await this.dataApi.getProducts();
      this.products.set(products);

      const selected = this.selectDefaultId(products.map((item) => item.id), this.selectedProductId());
      this.selectedProductId.set(selected);

      await this.loadScopes(silent);
      this.controlsStatus.set('loaded');
    } catch (error: unknown) {
      if (!silent) {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load products for graph context.'),
        );
        this.handleUnexpectedError(error);
        return;
      }
      if (statusBefore === 'idle') {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load products for graph context.'),
        );
        this.handleUnexpectedError(error);
      }
    }
  }

  private async loadScopes(silent = false): Promise<void> {
    const productId = this.selectedProductId();
    if (!productId) {
      this.scopes.set([]);
      this.selectedScopeId.set(null);
      this.tests.set([]);
      this.selectedTestId.set(null);
      this.revisions.set([]);
      this.selectedRevisionId.set('');
      return;
    }
    const statusBefore = this.controlsStatus();
    if (!silent) {
      this.controlsStatus.set('loading');
      this.controlsError.set(null);
    }
    try {
      const scopes = await this.dataApi.getScopes(productId);
      this.scopes.set(scopes);
      const selected = this.selectDefaultId(scopes.map((item) => item.id), this.selectedScopeId());
      this.selectedScopeId.set(selected);

      await this.loadTests(silent);
      this.controlsStatus.set('loaded');
    } catch (error: unknown) {
      if (!silent) {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load scopes for selected product.'),
        );
        this.handleUnexpectedError(error);
        return;
      }
      if (statusBefore === 'idle') {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load scopes for selected product.'),
        );
        this.handleUnexpectedError(error);
      }
    }
  }

  private async loadTests(silent = false): Promise<void> {
    const scopeId = this.selectedScopeId();
    if (!scopeId) {
      this.tests.set([]);
      this.selectedTestId.set(null);
      this.revisions.set([]);
      this.selectedRevisionId.set('');
      return;
    }
    const statusBefore = this.controlsStatus();
    if (!silent) {
      this.controlsStatus.set('loading');
      this.controlsError.set(null);
    }
    try {
      const tests = await this.dataApi.getTests(scopeId);
      this.tests.set(tests);
      const selected = this.selectDefaultId(tests.map((item) => item.id), this.selectedTestId());
      this.selectedTestId.set(selected);

      await this.loadRevisions(silent);
      this.controlsStatus.set('loaded');
    } catch (error: unknown) {
      if (!silent) {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load tests for selected scope.'),
        );
        this.handleUnexpectedError(error);
        return;
      }
      if (statusBefore === 'idle') {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load tests for selected scope.'),
        );
        this.handleUnexpectedError(error);
      }
    }
  }

  private async loadRevisions(silent = false): Promise<void> {
    const testId = this.selectedTestId();
    if (!testId) {
      this.revisions.set([]);
      this.selectedRevisionId.set('');
      return;
    }
    const statusBefore = this.controlsStatus();
    if (!silent) {
      this.controlsStatus.set('loading');
      this.controlsError.set(null);
    }
    try {
      const revisions = await this.dataApi.getRevisions(testId);
      this.revisions.set(revisions);
      if (!this.selectedRevisionId()) {
        this.selectedRevisionId.set('');
      }
      this.controlsStatus.set('loaded');
    } catch (error: unknown) {
      if (!silent) {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load revisions for selected test.'),
        );
        this.handleUnexpectedError(error);
        return;
      }
      if (statusBefore === 'idle') {
        this.controlsStatus.set('error');
        this.controlsError.set(
          this.resolveProblemDetail(error, 'Failed to load revisions for selected test.'),
        );
        this.handleUnexpectedError(error);
      }
    }
  }

  private resetGraphState(): void {
    this.chainResponse.set(EMPTY_CHAIN);
    this.graphStatus.set('idle');
    this.graphError.set(null);
    this.selectedNodeId.set(null);
    this.detailsByPurl.set(new Map());
    this.detailsStatus.set('idle');
    this.detailsError.set(null);
  }

  private selectDefaultId(ids: string[], current: string | null): string | null {
    if (current && ids.includes(current)) {
      return current;
    }
    return ids[0] ?? null;
  }

  private findById<T extends { id: string }>(items: T[], id: string | null): T | null {
    if (!id) {
      return null;
    }
    return items.find((item) => item.id === id) ?? null;
  }

  private resolveProblemDetail(error: unknown, fallback: string): string {
    if (!(error instanceof HttpErrorResponse)) {
      return fallback;
    }
    const detail = this.extractProblemDetail(error.error);
    if (detail) {
      return detail;
    }
    if (error.status === 404) {
      return 'Selected test or revision is no longer available in this project. Refresh selection and retry.';
    }
    if (error.status === 400) {
      return 'Invalid graph request parameters.';
    }
    return fallback;
  }

  private handleUnexpectedError(error: unknown): void {
    const status = this.resolveHttpStatus(error);
    if (status >= 400 && status < 500) {
      return;
    }
    this.errorHandler.handleError(error);
  }

  private resolveHttpStatus(error: unknown): number {
    if (error instanceof HttpErrorResponse) {
      return error.status ?? 0;
    }
    return 0;
  }

  private extractProblemDetail(errorBody: unknown): string | null {
    if (!errorBody || typeof errorBody !== 'object') {
      return null;
    }
    const detail = (errorBody as { detail?: unknown }).detail;
    if (typeof detail !== 'string') {
      return null;
    }
    const trimmed = detail.trim();
    return trimmed.length > 0 ? trimmed : null;
  }
}
