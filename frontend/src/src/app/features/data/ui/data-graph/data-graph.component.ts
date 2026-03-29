import { CommonModule } from '@angular/common';
import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  OnDestroy,
  ViewChild,
  computed,
  inject,
  signal,
} from '@angular/core';
import { Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { CopyButtonComponent } from '../../../../shared/ui/copy-button/copy-button.component';
import { ProjectContextService } from '../../../projects/data-access/project-context.service';
import { DataGraphStore } from '../../state/data-graph.store';
import {
  DataGraphComponentFinding,
  DataGraphNode,
  DataGraphOccurrence,
  DataGraphProducer,
  DataGraphQueueHistoryItem,
  DataGraphRawFinding,
} from '../../data-access/data-graph.types';
import { TestRevisionSummary } from '../../data-access/data.types';

interface ProducerOption {
  value: DataGraphProducer | '';
  label: string;
}

interface GraphNodeLayout extends DataGraphNode {
  x: number;
  y: number;
  width: number;
  height: number;
}

interface GraphEdgeLayout {
  id: string;
  from: string;
  to: string;
  relationshipType: string;
  path: string;
}

interface GraphLayout {
  width: number;
  height: number;
  nodes: GraphNodeLayout[];
  edges: GraphEdgeLayout[];
}

type FullscreenCapableDocument = Document & {
  webkitFullscreenElement?: Element | null;
  webkitExitFullscreen?: () => Promise<void> | void;
};

type FullscreenCapableElement = HTMLElement & {
  webkitRequestFullscreen?: () => Promise<void> | void;
};

const FINDING_COLUMNS: ColumnDefinition[] = [
  { key: 'malwarePurl', label: 'Malware PURL', sortKey: 'malwarePurl', filterKey: 'malwarePurl', className: 'mono' },
  { key: 'matchType', label: 'Match', sortKey: 'matchType', filterKey: 'matchType' },
  { key: 'triageStatus', label: 'Triage', sortKey: 'triageStatus', filterKey: 'triageStatus' },
  { key: 'effectivePriority', label: 'Priority', sortKey: 'effectivePriority', filterKey: 'effectivePriority' },
  { key: 'updatedAt', label: 'Updated', sortKey: 'updatedAt', filterKey: 'updatedAt' },
];

const RAW_FINDINGS_COLUMNS: ColumnDefinition[] = [
  { key: 'createdAt', label: 'Created', sortKey: 'createdAt', filterKey: 'createdAt' },
  { key: 'sourceId', label: 'Source', sortKey: 'sourceId', filterKey: 'sourceId', className: 'mono' },
  {
    key: 'resultFilename',
    label: 'Result file',
    sortKey: 'resultFilename',
    filterKey: 'resultFilename',
    className: 'mono',
  },
  { key: 'isMalware', label: 'Malware', sortKey: 'isMalware', filterKey: 'isMalware' },
  { key: 'publishedAt', label: 'Published', sortKey: 'publishedAt', filterKey: 'publishedAt' },
];

const QUEUE_COLUMNS: ColumnDefinition[] = [
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
  { key: 'reason', label: 'Reason', sortKey: 'reason', filterKey: 'reason' },
  { key: 'attempts', label: 'Attempts', sortKey: 'attempts', filterKey: 'attempts' },
  { key: 'updatedAt', label: 'Updated', sortKey: 'updatedAt', filterKey: 'updatedAt' },
  { key: 'lastError', label: 'Last error', sortKey: 'lastError', filterKey: 'lastError', className: 'mono' },
];

const OCCURRENCE_COLUMNS: ColumnDefinition[] = [
  { key: 'product', label: 'Product', sortKey: 'product', filterKey: 'product' },
  { key: 'scope', label: 'Scope', sortKey: 'scope', filterKey: 'scope' },
  { key: 'test', label: 'Test', sortKey: 'test', filterKey: 'test' },
  { key: 'revision', label: 'Revision', sortKey: 'revision', filterKey: 'revision', className: 'mono' },
  { key: 'producer', label: 'Producer', sortKey: 'producer', filterKey: 'producer' },
  { key: 'active', label: 'Active', sortKey: 'active', filterKey: 'active' },
];

@Component({
  selector: 'app-data-graph',
  imports: [
    CommonModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    DataTableComponent,
    CopyButtonComponent,
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-graph.component.html',
  styleUrl: './data-graph.component.scss',
})
export class DataGraphComponent implements OnDestroy {
  @ViewChild('graphViewport') private graphViewport?: ElementRef<HTMLElement>;
  @ViewChild('graphCardRoot', { read: ElementRef }) private graphCardRoot?: ElementRef<HTMLElement>;

  private readonly router = inject(Router);
  private readonly projectContext = inject(ProjectContextService);
  readonly store = inject(DataGraphStore);

  private readonly nodeWidth = 248;
  private readonly nodeHeight = 70;
  private readonly horizontalGap = 90;
  private readonly verticalGap = 24;
  private readonly margin = 32;

  private dragCleanup: (() => void) | null = null;
  private readonly fullscreenListener = (): void => {
    this.syncFullscreenState();
    if (this.getFullscreenElement()) {
      window.requestAnimationFrame(() => this.fitToView());
    }
  };
  private readonly webkitFullscreenListener = (): void => {
    this.syncFullscreenState();
    if (this.getFullscreenElement()) {
      window.requestAnimationFrame(() => this.fitToView());
    }
  };
  private readonly keydownListener = (event: KeyboardEvent): void => {
    if (event.key !== 'Escape') {
      return;
    }
    if (!this.isGraphPseudoFullscreen()) {
      return;
    }
    event.preventDefault();
    this.exitPseudoFullscreen();
  };
  private readonly fitRequested = signal(false);
  private fitRetryFrame: number | null = null;
  private fitRetryAttempts = 0;
  private previousBodyOverflow: string | null = null;
  private readonly bodyFullscreenClass = 'ctw-graph-fullscreen-mode';

  readonly selectedProjectName = computed(() => this.projectContext.selectedProjectName());
  readonly selectedProductLabel = computed(() => {
    const selectedId = this.store.selectedProductId();
    if (!selectedId) {
      return '';
    }
    const selected = this.store.products().find((item) => item.id === selectedId);
    return selected?.name ?? '';
  });
  readonly selectedNode = computed(() => this.store.selectedNode());
  readonly selectedDetails = computed(() => this.store.selectedDetails());

  readonly producerOptions: readonly ProducerOption[] = [
    { value: '', label: 'auto (active)' },
    { value: 'syft', label: 'syft' },
    { value: 'trivy', label: 'trivy' },
    { value: 'grype', label: 'grype' },
    { value: 'other', label: 'other' },
  ] as const;

  readonly findingColumns = FINDING_COLUMNS;
  readonly rawFindingColumns = RAW_FINDINGS_COLUMNS;
  readonly queueColumns = QUEUE_COLUMNS;
  readonly occurrenceColumns = OCCURRENCE_COLUMNS;

  readonly findingColumnOrder = signal(FINDING_COLUMNS.map((column) => column.key));
  readonly rawFindingColumnOrder = signal(RAW_FINDINGS_COLUMNS.map((column) => column.key));
  readonly queueColumnOrder = signal(QUEUE_COLUMNS.map((column) => column.key));
  readonly occurrenceColumnOrder = signal(OCCURRENCE_COLUMNS.map((column) => column.key));

  readonly zoom = signal(1);
  readonly zoomMin = 0.35;
  readonly zoomMax = 2.8;
  readonly zoomStep = 0.15;
  readonly isGraphFullscreen = signal(false);
  readonly isGraphPseudoFullscreen = signal(false);
  readonly isGraphInFullscreen = computed(
    () => this.isGraphFullscreen() || this.isGraphPseudoFullscreen(),
  );
  readonly graphSearch = signal('');

  readonly graphLayout = computed<GraphLayout>(() => this.buildGraphLayout());
  readonly scaledWidth = computed(() =>
    Math.max(420, Math.round(this.graphLayout().width * this.zoom())),
  );
  readonly scaledHeight = computed(() =>
    Math.max(280, Math.round(this.graphLayout().height * this.zoom())),
  );
  readonly graphViewBox = computed(() => {
    const layout = this.graphLayout();
    return `0 0 ${layout.width} ${layout.height}`;
  });
  readonly graphSearchQuery = computed(() => this.graphSearch().trim().toLowerCase());
  readonly hasGraphSearch = computed(() => this.graphSearchQuery().length > 0);
  readonly graphSearchNodeIDs = computed(() => {
    const query = this.graphSearchQuery();
    const matches = new Set<string>();
    if (!query) {
      return matches;
    }
    for (const node of this.graphLayout().nodes) {
      if (this.matchesGraphSearch(node, query)) {
        matches.add(node.id);
      }
    }
    return matches;
  });
  readonly graphSearchEdgeIDs = computed(() => {
    const matches = new Set<string>();
    const nodeIDs = this.graphSearchNodeIDs();
    if (!nodeIDs.size) {
      return matches;
    }
    for (const edge of this.graphLayout().edges) {
      if (nodeIDs.has(edge.from) || nodeIDs.has(edge.to)) {
        matches.add(edge.id);
      }
    }
    return matches;
  });
  readonly graphSearchRelatedNodeIDs = computed(() => {
    const related = new Set<string>();
    const searchEdges = this.graphSearchEdgeIDs();
    if (!searchEdges.size) {
      return related;
    }
    for (const edge of this.graphLayout().edges) {
      if (!searchEdges.has(edge.id)) {
        continue;
      }
      related.add(edge.from);
      related.add(edge.to);
    }
    return related;
  });
  readonly graphSearchMatchCount = computed(() => this.graphSearchNodeIDs().size);
  readonly graphSelection = computed(() => {
    const selectedID = this.store.selectedNodeId();
    if (!selectedID) {
      return {
        hasSelection: false,
        nodeIDs: new Set<string>(),
        edgeIDs: new Set<string>(),
      };
    }
    const highlightedNodes = new Set<string>([selectedID]);
    const highlightedEdges = new Set<string>();
    for (const edge of this.graphLayout().edges) {
      if (edge.from === selectedID || edge.to === selectedID) {
        highlightedEdges.add(edge.id);
        highlightedNodes.add(edge.from);
        highlightedNodes.add(edge.to);
      }
    }
    return {
      hasSelection: true,
      nodeIDs: highlightedNodes,
      edgeIDs: highlightedEdges,
    };
  });

  constructor() {
    document.addEventListener('fullscreenchange', this.fullscreenListener);
    document.addEventListener(
      'webkitfullscreenchange',
      this.webkitFullscreenListener as EventListener,
    );
    window.addEventListener('keydown', this.keydownListener);
    void this.store.initialize();
  }

  async onProductChange(productId: string): Promise<void> {
    await this.store.setProductId(productId || null);
  }

  async onScopeChange(scopeId: string): Promise<void> {
    await this.store.setScopeId(scopeId || null);
  }

  async onTestChange(testId: string): Promise<void> {
    await this.store.setTestId(testId || null);
  }

  onProducerChange(producer: DataGraphProducer | ''): void {
    this.store.setProducer(producer);
  }

  onRevisionChange(revisionId: string): void {
    this.store.setRevisionId(revisionId);
  }

  onMaxNodesInput(rawValue: string): void {
    const parsed = Number.parseInt(rawValue.trim(), 10);
    if (!Number.isFinite(parsed)) {
      return;
    }
    this.store.setMaxNodes(parsed);
  }

  onGraphSearchInput(rawValue: string): void {
    this.graphSearch.set(rawValue);
  }

  clearGraphSearch(): void {
    this.graphSearch.set('');
  }

  async renderGraph(): Promise<void> {
    this.fitRequested.set(true);
    this.fitRetryAttempts = 0;
    const rendered = await this.store.renderGraph();
    if (!rendered) {
      this.fitRequested.set(false);
      this.fitRetryAttempts = 0;
      return;
    }
    this.zoom.set(1);
    window.requestAnimationFrame(() => this.fitToView());
  }

  async onNodeClick(nodeId: string): Promise<void> {
    await this.store.selectNode(nodeId);
  }

  ngOnDestroy(): void {
    this.dragCleanup?.();
    this.dragCleanup = null;
    if (this.fitRetryFrame !== null) {
      window.cancelAnimationFrame(this.fitRetryFrame);
      this.fitRetryFrame = null;
    }
    this.fitRetryAttempts = 0;
    document.removeEventListener('fullscreenchange', this.fullscreenListener);
    document.removeEventListener(
      'webkitfullscreenchange',
      this.webkitFullscreenListener as EventListener,
    );
    window.removeEventListener('keydown', this.keydownListener);
    this.exitPseudoFullscreen();
  }

  onGraphWheel(event: WheelEvent): void {
    if (!event.ctrlKey && !event.metaKey) {
      return;
    }
    event.preventDefault();
    const direction = event.deltaY > 0 ? -1 : 1;
    this.adjustZoom(direction * this.zoomStep, event.clientX, event.clientY);
  }

  onViewportMouseDown(event: MouseEvent): void {
    if (event.button !== 0) {
      return;
    }
    const target = event.target;
    if (target instanceof HTMLElement && target.closest('.graph-node-btn')) {
      return;
    }
    if (!this.graphViewport) {
      return;
    }
    event.preventDefault();
    const viewport = this.graphViewport.nativeElement;
    const startX = event.clientX;
    const startY = event.clientY;
    const initialLeft = viewport.scrollLeft;
    const initialTop = viewport.scrollTop;
    viewport.classList.add('dragging');

    const onMove = (moveEvent: MouseEvent): void => {
      const dx = moveEvent.clientX - startX;
      const dy = moveEvent.clientY - startY;
      viewport.scrollLeft = initialLeft - dx;
      viewport.scrollTop = initialTop - dy;
    };
    const onUp = (): void => {
      viewport.classList.remove('dragging');
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      this.dragCleanup = null;
    };

    this.dragCleanup?.();
    this.dragCleanup = onUp;
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }

  zoomIn(): void {
    this.adjustZoom(this.zoomStep);
  }

  zoomOut(): void {
    this.adjustZoom(-this.zoomStep);
  }

  resetView(): void {
    this.zoom.set(1);
    window.requestAnimationFrame(() => this.centerViewport());
  }

  async toggleGraphFullscreen(): Promise<void> {
    const card = this.graphCardRoot?.nativeElement;
    if (!card) {
      return;
    }
    const fullscreenElement = this.getFullscreenElement();
    const cardIsNativeFullscreen =
      Boolean(fullscreenElement && (fullscreenElement === card || card.contains(fullscreenElement)));
    if (this.isGraphPseudoFullscreen() || cardIsNativeFullscreen) {
      if (cardIsNativeFullscreen) {
        try {
          await this.exitFullscreen();
        } catch {
          // Ignore native fullscreen exit errors and continue with app-level exit.
        }
      }
      this.exitPseudoFullscreen();
      window.requestAnimationFrame(() => this.fitToView());
      return;
    }

    // Deterministic app fullscreen: always enable pseudo fullscreen first.
    this.enterPseudoFullscreen();
    window.requestAnimationFrame(() => this.fitToView());
  }

  fitToView(): void {
    const viewport = this.graphViewport?.nativeElement;
    const layout = this.graphLayout();
    if (!viewport || layout.width <= 0 || layout.height <= 0) {
      this.scheduleFitRetry();
      return;
    }
    const availableWidth = Math.max(120, viewport.clientWidth - 12);
    const availableHeight = Math.max(120, viewport.clientHeight - 12);
    const fit = Math.min(availableWidth / layout.width, availableHeight / layout.height);
    const normalized = Math.max(this.zoomMin, Math.min(this.zoomMax, fit));
    this.zoom.set(normalized);
    window.requestAnimationFrame(() => this.centerViewport());
    if (this.fitRetryFrame !== null) {
      window.cancelAnimationFrame(this.fitRetryFrame);
      this.fitRetryFrame = null;
    }
    this.fitRetryAttempts = 0;
    this.fitRequested.set(false);
  }

  openExplorer(): void {
    const node = this.selectedNode();
    if (!node) {
      return;
    }
    const details = this.selectedDetails();
    void this.router.navigate(['/security/explorer'], {
      queryParams: {
        componentPurl: node.purl,
        focusProductId: details?.identity.productId ?? null,
        focusScopeId: details?.identity.scopeId ?? null,
        focusTestId: details?.identity.testId ?? null,
      },
    });
  }

  openDataTestDetails(): void {
    const node = this.selectedNode();
    if (!node) {
      return;
    }
    const details = this.selectedDetails();
    const metadata = this.store.graphMetadata();
    const productId = details?.identity.productId ?? metadata.productId;
    const scopeId = details?.identity.scopeId ?? metadata.scopeId;
    const testId = details?.identity.testId ?? metadata.testId;
    if (!productId || !scopeId || !testId) {
      return;
    }
    void this.router.navigate(['/data'], {
      queryParams: {
        section: 'tests',
        productId,
        scopeId,
        testId,
        detail: '1',
        componentQ: node.purl,
      },
    });
  }

  findingRowValue(row: DataGraphComponentFinding, column: string): string {
    if (column === 'updatedAt') {
      return this.formatDateTime(row.updatedAt ?? null);
    }
    if (column === 'triageStatus') {
      return row.triageStatus || 'OPEN';
    }
    if (column === 'effectivePriority') {
      return row.effectivePriority || '-';
    }
    if (column === 'matchType') {
      return row.matchType || '-';
    }
    return row.malwarePurl || '-';
  }

  rawFindingRowValue(row: DataGraphRawFinding, column: string): string {
    if (column === 'createdAt') {
      return this.formatDateTime(row.createdAt ?? null);
    }
    if (column === 'sourceId') {
      return row.sourceId || '-';
    }
    if (column === 'resultFilename') {
      return row.resultFilename || '-';
    }
    if (column === 'isMalware') {
      return row.isMalware ? 'YES' : 'NO';
    }
    return this.formatDateTime(row.publishedAt ?? null);
  }

  queueRowValue(row: DataGraphQueueHistoryItem, column: string): string {
    if (column === 'status') {
      return row.status || '-';
    }
    if (column === 'reason') {
      return row.reason || '-';
    }
    if (column === 'attempts') {
      return this.formatNumber(row.attempts ?? 0);
    }
    if (column === 'updatedAt') {
      return this.formatDateTime(row.updatedAt ?? null);
    }
    return row.lastError || '-';
  }

  occurrenceRowValue(row: DataGraphOccurrence, column: string): string {
    if (column === 'product') {
      return row.productName || '-';
    }
    if (column === 'scope') {
      return row.scopeName || '-';
    }
    if (column === 'test') {
      return row.testName || '-';
    }
    if (column === 'revision') {
      return row.revisionId || '-';
    }
    if (column === 'producer') {
      return row.sbomProducer || '-';
    }
    return row.revisionIsActive ? 'YES' : 'NO';
  }

  formatNumber(value: number): string {
    return new Intl.NumberFormat().format(value);
  }

  formatDateTime(input: string | null | undefined): string {
    if (!input) {
      return 'N/A';
    }
    const parsed = Date.parse(input);
    if (Number.isNaN(parsed)) {
      return 'N/A';
    }
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    }).format(parsed);
  }

  formatRelative(input: string | null | undefined): string {
    if (!input) {
      return 'N/A';
    }
    const timestamp = Date.parse(input);
    if (Number.isNaN(timestamp)) {
      return 'N/A';
    }
    const diffMs = Date.now() - timestamp;
    if (diffMs < 0) {
      return 'just now';
    }
    const minutes = Math.floor(diffMs / 60_000);
    if (minutes < 1) {
      return 'just now';
    }
    if (minutes < 60) {
      return `${minutes}m ago`;
    }
    const hours = Math.floor(minutes / 60);
    if (hours < 24) {
      return `${hours}h ago`;
    }
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  revisionOptionLabel(revision: TestRevisionSummary): string {
    const marker = revision.isActive ? 'active' : 'archived';
    const created = this.formatDateTime(revision.createdAt ?? null);
    const producer = revision.sbomProducer ? ` · ${revision.sbomProducer}` : '';
    return `${revision.id} · ${marker}${producer} · ${created}`;
  }

  verdictClass(verdict: string): string {
    const normalized = verdict.trim().toUpperCase();
    if (normalized === 'MALWARE') {
      return 'badge badge-danger';
    }
    if (normalized === 'CLEAN') {
      return 'badge badge-success';
    }
    return 'badge badge-warning';
  }

  nodeClass(node: GraphNodeLayout): string {
    const classes = ['graph-node-btn'];
    if (node.isMalware) {
      classes.push('graph-node-btn--malware');
    } else {
      classes.push('graph-node-btn--clean');
    }
    if (this.selectedNodeId(node.id)) {
      classes.push('graph-node-btn--selected');
    }
    if (this.hasGraphSearch()) {
      const searchMatches = this.graphSearchNodeIDs();
      if (searchMatches.has(node.id)) {
        classes.push('graph-node-btn--search-match');
      } else if (this.graphSearchRelatedNodeIDs().has(node.id)) {
        classes.push('graph-node-btn--related');
      } else {
        classes.push('graph-node-btn--search-dim');
      }
      return classes.join(' ');
    }
    const selection = this.graphSelection();
    if (selection.hasSelection) {
      if (selection.nodeIDs.has(node.id) && !this.selectedNodeId(node.id)) {
        classes.push('graph-node-btn--related');
      }
      return classes.join(' ');
    }
    return classes.join(' ');
  }

  edgeClass(edge: GraphEdgeLayout): string {
    const classes = ['graph-edge'];
    const selection = this.graphSelection();
    if (selection.hasSelection) {
      if (selection.edgeIDs.has(edge.id)) {
        classes.push('graph-edge--highlight');
      } else {
        classes.push('graph-edge--dim');
      }
      return classes.join(' ');
    }
    if (this.hasGraphSearch()) {
      // Search highlights matched nodes only. Keep edge/connection styling unchanged.
      return classes.join(' ');
    }
    return classes.join(' ');
  }

  selectedNodeId(nodeId: string): boolean {
    return this.store.selectedNodeId() === nodeId;
  }

  nodeLinePrimary(node: DataGraphNode): string {
    const label = node.label || node.purl;
    const atIdx = label.indexOf('@');
    if (atIdx > 0) {
      return label.slice(0, atIdx);
    }
    return label;
  }

  nodeLineSecondary(node: DataGraphNode): string {
    const label = node.label || node.purl;
    const atIdx = label.indexOf('@');
    if (atIdx > 0) {
      return label.slice(atIdx + 1);
    }
    return node.pkgType || node.version || '-';
  }

  identityJson(value: unknown): string {
    if (value === null || value === undefined) {
      return '';
    }
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  private adjustZoom(delta: number, clientX?: number, clientY?: number): void {
    const viewport = this.graphViewport?.nativeElement;
    const currentZoom = this.zoom();
    const next = currentZoom + delta;
    const normalized = Math.max(this.zoomMin, Math.min(this.zoomMax, next));
    if (!viewport) {
      this.zoom.set(Number(normalized.toFixed(3)));
      return;
    }
    if (Math.abs(normalized - currentZoom) < 0.001) {
      return;
    }
    const rect = viewport.getBoundingClientRect();
    const cursorX =
      typeof clientX === 'number' ? Math.max(0, Math.min(rect.width, clientX - rect.left)) : rect.width / 2;
    const cursorY =
      typeof clientY === 'number' ? Math.max(0, Math.min(rect.height, clientY - rect.top)) : rect.height / 2;
    const anchorWorldX = (viewport.scrollLeft + cursorX) / currentZoom;
    const anchorWorldY = (viewport.scrollTop + cursorY) / currentZoom;
    this.zoom.set(Number(normalized.toFixed(3)));
    window.requestAnimationFrame(() => {
      viewport.scrollLeft = anchorWorldX * normalized - cursorX;
      viewport.scrollTop = anchorWorldY * normalized - cursorY;
    });
  }

  private centerViewport(): void {
    const viewport = this.graphViewport?.nativeElement;
    if (!viewport) {
      return;
    }
    const left = Math.max(0, (this.scaledWidth() - viewport.clientWidth) / 2);
    const top = Math.max(0, (this.scaledHeight() - viewport.clientHeight) / 2);
    viewport.scrollLeft = left;
    viewport.scrollTop = top;
  }

  private scheduleFitRetry(): void {
    if (!this.fitRequested() || this.fitRetryFrame !== null) {
      return;
    }
    if (this.fitRetryAttempts >= 20) {
      this.fitRequested.set(false);
      this.fitRetryAttempts = 0;
      return;
    }
    this.fitRetryAttempts += 1;
    this.fitRetryFrame = window.requestAnimationFrame(() => {
      this.fitRetryFrame = null;
      this.fitToView();
    });
  }

  private syncFullscreenState(): void {
    const card = this.graphCardRoot?.nativeElement;
    const fullscreenElement = this.getFullscreenElement();
    this.isGraphFullscreen.set(
      Boolean(card && fullscreenElement && (fullscreenElement === card || card.contains(fullscreenElement))),
    );
  }

  private isElementInFullscreen(element: HTMLElement): boolean {
    const fullscreenElement = this.getFullscreenElement();
    return Boolean(fullscreenElement && (fullscreenElement === element || element.contains(fullscreenElement)));
  }

  private async waitForFullscreenSync(): Promise<void> {
    await new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });
  }

  private getFullscreenElement(): Element | null {
    const doc = document as FullscreenCapableDocument;
    return doc.fullscreenElement ?? doc.webkitFullscreenElement ?? null;
  }

  private async requestFullscreen(element: HTMLElement): Promise<boolean> {
    const target = element as FullscreenCapableElement;
    if (typeof target.requestFullscreen === 'function') {
      await target.requestFullscreen();
      await this.waitForFullscreenSync();
      this.syncFullscreenState();
      return this.isElementInFullscreen(element);
    }
    if (typeof target.webkitRequestFullscreen === 'function') {
      await target.webkitRequestFullscreen();
      await this.waitForFullscreenSync();
      this.syncFullscreenState();
      return this.isElementInFullscreen(element);
    }
    return false;
  }

  private async exitFullscreen(): Promise<boolean> {
    const doc = document as FullscreenCapableDocument;
    if (typeof doc.exitFullscreen === 'function') {
      await doc.exitFullscreen();
      await this.waitForFullscreenSync();
      this.syncFullscreenState();
      return this.getFullscreenElement() === null;
    }
    if (typeof doc.webkitExitFullscreen === 'function') {
      await doc.webkitExitFullscreen();
      await this.waitForFullscreenSync();
      this.syncFullscreenState();
      return this.getFullscreenElement() === null;
    }
    return false;
  }

  private enterPseudoFullscreen(): void {
    if (!this.isGraphPseudoFullscreen()) {
      this.previousBodyOverflow = document.body.style.overflow;
      document.body.style.overflow = 'hidden';
      document.body.classList.add(this.bodyFullscreenClass);
    }
    this.isGraphPseudoFullscreen.set(true);
  }

  private exitPseudoFullscreen(): void {
    this.isGraphPseudoFullscreen.set(false);
    document.body.classList.remove(this.bodyFullscreenClass);
    if (this.previousBodyOverflow !== null) {
      document.body.style.overflow = this.previousBodyOverflow;
      this.previousBodyOverflow = null;
    }
  }

  private matchesGraphSearch(node: DataGraphNode, query: string): boolean {
    if (!query) {
      return true;
    }
    const fields = [
      node.label,
      node.purl,
      node.pkgType,
      node.pkgNamespace ?? '',
      node.version ?? '',
      node.isMalware ? 'malware' : 'clean',
    ];
    for (const field of fields) {
      if (field.toLowerCase().includes(query)) {
        return true;
      }
    }
    return false;
  }

  private buildGraphLayout(): GraphLayout {
    const nodes = this.store.graphNodes();
    if (nodes.length === 0) {
      return {
        width: 0,
        height: 0,
        nodes: [],
        edges: [],
      };
    }

    const nodeByID = new Map(nodes.map((node) => [node.id, node]));
    const incomingCount = new Map<string, number>();
    const outgoing = new Map<string, string[]>();
    const level = new Map<string, number>();

    for (const node of nodes) {
      incomingCount.set(node.id, 0);
      outgoing.set(node.id, []);
      level.set(node.id, 0);
    }

    const filteredEdges = this.store.graphEdges().filter((edge) => {
      const fromExists = nodeByID.has(edge.from);
      const toExists = nodeByID.has(edge.to);
      if (!fromExists || !toExists) {
        return false;
      }
      outgoing.get(edge.from)?.push(edge.to);
      incomingCount.set(edge.to, (incomingCount.get(edge.to) ?? 0) + 1);
      return true;
    });

    const queue: string[] = [];
    for (const node of nodes) {
      if ((incomingCount.get(node.id) ?? 0) === 0) {
        queue.push(node.id);
      }
    }

    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) {
        continue;
      }
      const currentLevel = level.get(current) ?? 0;
      const targets = outgoing.get(current) ?? [];
      for (const target of targets) {
        const nextLevel = Math.max(level.get(target) ?? 0, currentLevel + 1);
        level.set(target, nextLevel);
        const left = (incomingCount.get(target) ?? 1) - 1;
        incomingCount.set(target, left);
        if (left === 0) {
          queue.push(target);
        }
      }
    }

    const grouped = new Map<number, DataGraphNode[]>();
    for (const node of nodes) {
      const nodeLevel = level.get(node.id) ?? 0;
      const current = grouped.get(nodeLevel) ?? [];
      current.push(node);
      grouped.set(nodeLevel, current);
    }
    for (const group of grouped.values()) {
      group.sort((a, b) => a.label.localeCompare(b.label));
    }

    const levels = Array.from(grouped.keys()).sort((a, b) => a - b);
    const maxRows = levels.reduce((acc, key) => Math.max(acc, grouped.get(key)?.length ?? 0), 1);
    const maxLevel = levels.length > 0 ? levels[levels.length - 1] : 0;

    const width =
      this.margin * 2 + this.nodeWidth * (maxLevel + 1) + this.horizontalGap * Math.max(0, maxLevel);
    const height =
      this.margin * 2 + this.nodeHeight * maxRows + this.verticalGap * Math.max(0, maxRows - 1);

    const positionedNodes: GraphNodeLayout[] = [];
    for (const currentLevel of levels) {
      const group = grouped.get(currentLevel) ?? [];
      const groupHeight =
        group.length * this.nodeHeight + Math.max(0, group.length - 1) * this.verticalGap;
      const startY = this.margin + Math.max(0, (height - this.margin * 2 - groupHeight) / 2);
      let index = 0;
      for (const source of group) {
        positionedNodes.push({
          ...source,
          x: this.margin + currentLevel * (this.nodeWidth + this.horizontalGap),
          y: startY + index * (this.nodeHeight + this.verticalGap),
          width: this.nodeWidth,
          height: this.nodeHeight,
        });
        index += 1;
      }
    }

    const positionedByID = new Map(positionedNodes.map((node) => [node.id, node]));
    const positionedEdges: GraphEdgeLayout[] = [];
    for (const edge of filteredEdges) {
      const from = positionedByID.get(edge.from);
      const to = positionedByID.get(edge.to);
      if (!from || !to) {
        continue;
      }
      const startX = from.x + from.width;
      const startY = from.y + from.height / 2;
      const endX = to.x;
      const endY = to.y + to.height / 2;
      const curve = Math.max(42, Math.abs(endX - startX) * 0.4);
      const path = `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`;
      positionedEdges.push({
        id: `${edge.from}->${edge.to}:${edge.relationshipType}`,
        from: edge.from,
        to: edge.to,
        relationshipType: edge.relationshipType,
        path,
      });
    }

    return {
      width,
      height,
      nodes: positionedNodes,
      edges: positionedEdges,
    };
  }
}
