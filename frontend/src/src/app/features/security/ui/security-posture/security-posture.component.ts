
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from '@angular/core';
import { Router } from '@angular/router';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatSelectModule } from '@angular/material/select';
import { ProjectContextService } from '../../../projects/data-access/project-context.service';
import { LoadingIndicatorComponent } from '../../../../shared/ui/loading-indicator/loading-indicator.component';
import { DataTableComponent } from '../../../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import { SecurityPostureFailure, SecurityPostureUpload } from '../../data-access/security.types';
import { SecurityPostureStore } from '../../state/security-posture.store';

const recentUploadColumns: ColumnDefinition[] = [
  { key: 'timestamp', label: 'When', sortKey: 'timestamp', filterKey: 'timestamp' },
  { key: 'target', label: 'Target', sortKey: 'target', filterKey: 'target' },
  { key: 'summary', label: 'Summary', sortKey: 'summary', filterKey: 'summary' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
];

const recentFailureColumns: ColumnDefinition[] = [
  { key: 'timestamp', label: 'When', sortKey: 'timestamp', filterKey: 'timestamp' },
  { key: 'component', label: 'Component', sortKey: 'component', filterKey: 'component' },
  { key: 'summary', label: 'Summary', sortKey: 'summary', filterKey: 'summary' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
];

interface TimelinePoint {
  index: number;
  bucketStart: string;
  bucketLabel: string;
  x: number;
  primaryY: number;
  secondaryY: number;
  primaryValue: number;
  secondaryValue: number;
}

interface TimelineChart {
  hasData: boolean;
  primaryLine: string;
  primaryArea: string;
  secondaryLine: string;
  points: TimelinePoint[];
  yMin: number;
  yMax: number;
  yGrid: number[];
  labels: [string, string, string];
}

interface TimelineRelatedEvent {
  timestamp: string;
  component: string;
  summary: string;
  status: string;
}

interface TimelineSelection {
  index: number;
  bucketLabel: string;
  bucketStart: string;
  primaryLabel: string;
  secondaryLabel: string;
  primaryValue: number;
  secondaryValue: number;
  primaryDelta: number | null;
  secondaryDelta: number | null;
  failureRatePercent: number | null;
  pointX: number;
  relatedEvents: TimelineRelatedEvent[];
}

interface TimelineTooltip {
  leftPercent: number;
  topPercent: number;
  timestampLabel: string;
  primaryLabel: string;
  secondaryLabel: string;
  primaryValue: number;
  secondaryValue: number;
}

const TIMELINE_VIEWBOX_WIDTH = 420;
const TIMELINE_VIEWBOX_HEIGHT = 150;

@Component({
  selector: 'app-security-posture',
  imports: [
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    DataTableComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './security-posture.component.html',
  styleUrl: './security-posture.component.scss',
})
export class SecurityPostureComponent implements OnInit {
  private readonly router = inject(Router);
  private readonly projectContext = inject(ProjectContextService);
  readonly store = inject(SecurityPostureStore);

  readonly topNAllValue = 0;
  readonly topNAllLabel = 'ALL';
  private readonly baseTopNOptions: number[] = [5, 10, 25, 50, 100, 250, 500, 1000];
  readonly topNOptions = computed<number[]>(() => {
    const values = [...this.baseTopNOptions];
    const current = this.store.topN();
    if (current > 0 && !values.includes(current)) {
      values.push(current);
      values.sort((a, b) => a - b);
    }
    return [...values, this.topNAllValue];
  });
  readonly selectedIngestPointIndex = signal<number | null>(null);
  readonly selectedOsvPointIndex = signal<number | null>(null);
  readonly hoveredIngestPointIndex = signal<number | null>(null);
  readonly hoveredOsvPointIndex = signal<number | null>(null);
  readonly selectedProjectName = computed(() => this.projectContext.selectedProjectName());

  readonly data = computed(() => this.store.data());
  readonly kpis = computed(() => this.store.data().kpis);
  readonly ingestTrend = computed(() => this.store.data().ingestTrend);
  readonly osvSyncTrend = computed(() => this.store.data().osvSyncTrend);
  readonly recentUploads = computed(() => this.store.data().recentUploads);
  readonly recentFailures = computed(() => this.store.data().recentFailures);
  readonly topNLabel = computed(() => this.topNDisplay(this.data().topN));
  readonly uploadColumns = recentUploadColumns;
  readonly failureColumns = recentFailureColumns;
  readonly uploadColumnOrder = signal(['timestamp', 'target', 'summary', 'status']);
  readonly failureColumnOrder = signal(['timestamp', 'component', 'summary', 'status']);
  readonly scoreTotalProducts = computed(() => Math.max(0, this.kpis().totalProducts));
  readonly scoreMalwareProducts = computed(() => {
    const total = this.scoreTotalProducts();
    return Math.min(total, Math.max(0, this.kpis().malwareProducts));
  });
  readonly scoreSafeProducts = computed(() =>
    Math.max(0, this.scoreTotalProducts() - this.scoreMalwareProducts()),
  );
  readonly scoreSafeRatio = computed(() => {
    const total = this.scoreTotalProducts();
    if (total <= 0) {
      return 0;
    }
    return Math.max(0, Math.min(1, this.scoreSafeProducts() / total));
  });

  readonly scoreRingColor = computed(() => 'var(--ctw-success-text)');

  readonly scoreRing = computed(() => {
    const angle = this.scoreSafeRatio() * 360;
    return `conic-gradient(${this.scoreRingColor()} 0deg ${angle}deg, var(--ctw-border-subtle) ${angle}deg 360deg)`;
  });

  readonly scoreColor = computed(() => this.scoreRingColor());

  readonly ingestTimeline = computed<TimelineChart>(() => {
    const trend = this.ingestTrend();
    return this.createTimeline(
      trend.map((item) => item.bucketStart),
      trend.map((item) => item.imports),
      trend.map((item) => item.failures),
    );
  });

  readonly osvTimeline = computed<TimelineChart>(() => {
    const trend = this.osvSyncTrend();
    return this.createTimeline(
      trend.map((item) => item.bucketStart),
      trend.map((item) => item.runs),
      trend.map((item) => item.failures),
    );
  });
  readonly ingestSelection = computed<TimelineSelection | null>(() =>
    this.buildTimelineSelection(
      this.ingestTimeline(),
      this.selectedIngestPointIndex(),
      'ingest',
      'Imports',
      'Failures',
    ),
  );
  readonly osvSelection = computed<TimelineSelection | null>(() =>
    this.buildTimelineSelection(
      this.osvTimeline(),
      this.selectedOsvPointIndex(),
      'osv',
      'Sync runs',
      'Errors',
    ),
  );
  readonly ingestTooltip = computed<TimelineTooltip | null>(() =>
    this.buildTimelineTooltip(
      this.ingestTimeline(),
      this.hoveredIngestPointIndex(),
      this.selectedIngestPointIndex(),
      'Imports',
      'Failures',
    ),
  );
  readonly osvTooltip = computed<TimelineTooltip | null>(() =>
    this.buildTimelineTooltip(
      this.osvTimeline(),
      this.hoveredOsvPointIndex(),
      this.selectedOsvPointIndex(),
      'Sync runs',
      'Errors',
    ),
  );

  ngOnInit(): void {
    void this.store.ensureFresh();
  }

  async onTopNChange(topN: number): Promise<void> {
    await this.store.setTopN(topN);
  }

  formatInteger(value: number): string {
    return new Intl.NumberFormat().format(value);
  }

  formatPercent(value: number): string {
    return `${Math.round(value)}%`;
  }

  selectIngestPoint(index: number): void {
    this.selectedIngestPointIndex.set(index);
  }

  selectOsvPoint(index: number): void {
    this.selectedOsvPointIndex.set(index);
  }

  onTimelinePointKeydown(event: KeyboardEvent, chart: 'ingest' | 'osv', index: number): void {
    if (event.key !== 'Enter' && event.key !== ' ') {
      return;
    }
    event.preventDefault();
    if (chart === 'ingest') {
      this.selectIngestPoint(index);
      return;
    }
    this.selectOsvPoint(index);
  }

  setTimelineHover(chart: 'ingest' | 'osv', index: number | null): void {
    if (chart === 'ingest') {
      this.hoveredIngestPointIndex.set(index);
      return;
    }
    this.hoveredOsvPointIndex.set(index);
  }

  timelineDeltaText(value: number | null): string {
    if (value === null) {
      return 'vs previous: n/a';
    }
    if (value === 0) {
      return 'vs previous: no change';
    }
    const direction = value > 0 ? '+' : '';
    return `vs previous: ${direction}${this.formatInteger(value)}`;
  }

  timelinePointAria(point: TimelinePoint, primaryLabel: string, secondaryLabel: string): string {
    return `${this.formatTimelineTimestamp(point.bucketStart)}: ${primaryLabel} ${point.primaryValue}, ${secondaryLabel} ${point.secondaryValue}`;
  }

  timelinePointTooltip(point: TimelinePoint, primaryLabel: string, secondaryLabel: string): string {
    return `${this.formatTimelineTimestamp(point.bucketStart)} | ${primaryLabel}: ${this.formatInteger(point.primaryValue)} | ${secondaryLabel}: ${this.formatInteger(point.secondaryValue)}`;
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

  failureRowValue(row: SecurityPostureFailure, column: string): string {
    if (column === 'timestamp') {
      return this.formatRelative(row.timestamp);
    }
    if (column === 'status') {
      return row.status.toUpperCase();
    }
    if (column === 'component') {
      return row.component;
    }
    return row.summary;
  }

  uploadRowValue(row: SecurityPostureUpload, column: string): string {
    if (column === 'timestamp') {
      return this.formatRelative(row.timestamp);
    }
    if (column === 'target') {
      return this.uploadTarget(row);
    }
    if (column === 'summary') {
      return this.uploadSummary(row);
    }
    return this.normalizeUploadStatus(row.status);
  }

  uploadBadgeClass(status: string): string {
    const normalized = this.normalizeUploadStatus(status);
    if (normalized === 'FAILED' || normalized === 'ERROR') {
      return 'badge badge-danger';
    }
    if (normalized === 'COMPLETED') {
      return 'badge badge-ok';
    }
    return 'badge badge-muted';
  }

  normalizeUploadStatus(status: string): string {
    const normalized = status.trim().toUpperCase();
    if (!normalized) {
      return 'UNKNOWN';
    }
    return normalized;
  }

  failureBadgeClass(status: string): string {
    const normalized = status.trim().toUpperCase();
    if (normalized === 'FAILED' || normalized === 'ERROR') {
      return 'badge badge-danger';
    }
    return 'badge badge-muted';
  }

  openSources(): void {
    void this.router.navigate(['/security/sources']);
  }

  openExplorer(): void {
    void this.router.navigate(['/security/explorer']);
  }

  openIngest(): void {
    void this.router.navigate(['/data/import']);
  }

  openUpload(row: SecurityPostureUpload): void {
    const testID = (row.testId ?? '').trim();
    if (testID) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'tests',
          productId: (row.productId ?? '').trim() || null,
          scopeId: (row.scopeId ?? '').trim() || null,
          testId: testID,
          detail: '1',
        },
      });
      return;
    }
    const scopeID = (row.scopeId ?? '').trim();
    if (scopeID) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'tests',
          productId: (row.productId ?? '').trim() || null,
          scopeId: scopeID,
        },
      });
      return;
    }
    const productID = (row.productId ?? '').trim();
    if (productID) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'scopes',
          productId: productID,
        },
      });
      return;
    }
    this.openIngest();
  }

  openFailure(row: SecurityPostureFailure): void {
    if (row.component.startsWith('source_sync')) {
      this.openSources();
      return;
    }
    this.openIngest();
  }

  uploadTarget(row: SecurityPostureUpload): string {
    const parts = [row.productName, row.scopeName, row.testName]
      .map((value) => value.trim())
      .filter(Boolean);
    if (!parts.length) {
      return 'N/A';
    }
    return parts.join(' / ');
  }

  uploadSummary(row: SecurityPostureUpload): string {
    const components = `${this.formatInteger(Math.max(0, row.componentsImported))} components`;
    const stage = row.stage.trim();
    const status = this.normalizeUploadStatus(row.status);
    if ((status === 'FAILED' || status === 'ERROR') && row.errorMessage) {
      return `${stage || status}: ${row.errorMessage}`;
    }
    if (stage) {
      return `${stage} (${components})`;
    }
    return components;
  }

  private createTimeline(
    buckets: string[],
    primaryValues: number[],
    secondaryValues: number[],
  ): TimelineChart {
    const width = TIMELINE_VIEWBOX_WIDTH;
    const height = TIMELINE_VIEWBOX_HEIGHT;
    const xMin = 34;
    const xMax = width - 12;
    const yMin = 12;
    const yMax = height - 34;
    const chartHeight = yMax - yMin;
    const chartWidth = xMax - xMin;

    if (!primaryValues.length) {
      const baseY = yMax;
      return {
        hasData: false,
        primaryLine: `M${xMin},${baseY} L${xMax},${baseY}`,
        primaryArea: `M${xMin},${yMax} L${xMin},${baseY} L${xMax},${baseY} L${xMax},${yMax} Z`,
        secondaryLine: `M${xMin},${baseY} L${xMax},${baseY}`,
        points: [],
        yMin,
        yMax,
        yGrid: [yMin, yMin + chartHeight / 3, yMin + (2 * chartHeight) / 3, yMax],
        labels: ['N/A', 'N/A', 'N/A'],
      };
    }

    const normalizedPrimary = primaryValues.map((value) => Math.max(0, value));
    const normalizedSecondary = secondaryValues.map((value) => Math.max(0, value));
    const maxPrimary = Math.max(...normalizedPrimary, 1);
    const maxSecondary = Math.max(...normalizedSecondary, 1);
    const maxCombined = Math.max(maxPrimary, maxSecondary, 1);
    const step = normalizedPrimary.length > 1 ? chartWidth / (normalizedPrimary.length - 1) : 0;

    const points: TimelinePoint[] = [];
    let index = 0;
    for (const value of normalizedPrimary) {
      const x = xMin + index * step;
      const primaryY = yMax - (value / maxCombined) * chartHeight;
      let secondaryValue = 0;
      let secondaryIndex = 0;
      for (const candidate of normalizedSecondary) {
        if (secondaryIndex === index) {
          secondaryValue = candidate;
          break;
        }
        secondaryIndex += 1;
      }
      const secondaryY = yMax - (secondaryValue / maxCombined) * chartHeight;
      const bucketStart = this.timelineBucketAt(buckets, index);
      points.push({
        index,
        bucketStart,
        bucketLabel: this.formatTimelineLabel(bucketStart),
        x,
        primaryY,
        secondaryY,
        primaryValue: value,
        secondaryValue,
      });
      index += 1;
    }

    const primaryLine = `M${points
      .map((point) => `${point.x.toFixed(2)},${point.primaryY.toFixed(2)}`)
      .join(' L')}`;
    const primaryArea = `M${xMin},${yMax} L${points
      .map((point) => `${point.x.toFixed(2)},${point.primaryY.toFixed(2)}`)
      .join(' L')} L${xMax},${yMax} Z`;
    const secondaryLine = `M${points
      .map((point) => `${point.x.toFixed(2)},${point.secondaryY.toFixed(2)}`)
      .join(' L')}`;

    const labels: [string, string, string] = [
      this.timelineBucketLabel(buckets, 'start'),
      this.timelineBucketLabel(buckets, 'middle'),
      this.timelineBucketLabel(buckets, 'end'),
    ];

    return {
      hasData: true,
      primaryLine,
      primaryArea,
      secondaryLine,
      points,
      yMin,
      yMax,
      yGrid: [yMin, yMin + chartHeight / 3, yMin + (2 * chartHeight) / 3, yMax],
      labels,
    };
  }

  private formatTimelineLabel(input: string | null): string {
    if (!input) {
      return 'N/A';
    }
    const timestamp = Date.parse(input);
    if (Number.isNaN(timestamp)) {
      return 'N/A';
    }
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' }).format(timestamp);
  }

  private formatTimelineTimestamp(input: string | null): string {
    if (!input) {
      return 'N/A';
    }
    const timestamp = Date.parse(input);
    if (Number.isNaN(timestamp)) {
      return 'N/A';
    }
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    }).format(timestamp);
  }

  private timelineBucketLabel(buckets: string[], position: 'start' | 'middle' | 'end'): string {
    if (!buckets.length) {
      return 'N/A';
    }
    const targetIndex =
      position === 'start'
        ? 0
        : position === 'end'
          ? buckets.length - 1
          : Math.floor((buckets.length - 1) / 2);
    let current = 0;
    for (const bucket of buckets) {
      if (current === targetIndex) {
        return this.formatTimelineLabel(bucket);
      }
      current += 1;
    }
    return 'N/A';
  }

  private timelineBucketAt(buckets: string[], targetIndex: number): string {
    let index = 0;
    for (const bucket of buckets) {
      if (index === targetIndex) {
        return bucket;
      }
      index += 1;
    }
    return '';
  }

  private buildTimelineSelection(
    chart: TimelineChart,
    selectedIndex: number | null,
    kind: 'ingest' | 'osv',
    primaryLabel: string,
    secondaryLabel: string,
  ): TimelineSelection | null {
    const selected = this.resolveTimelinePoint(chart.points, selectedIndex);
    if (!selected) {
      return null;
    }
    const previous = this.resolveTimelinePoint(chart.points, selected.index - 1);
    const primaryDelta = previous ? selected.primaryValue - previous.primaryValue : null;
    const secondaryDelta = previous ? selected.secondaryValue - previous.secondaryValue : null;
    const failureRatePercent =
      selected.primaryValue > 0 ? (selected.secondaryValue / selected.primaryValue) * 100 : null;
    return {
      index: selected.index,
      bucketLabel: selected.bucketLabel,
      bucketStart: selected.bucketStart,
      primaryLabel,
      secondaryLabel,
      primaryValue: selected.primaryValue,
      secondaryValue: selected.secondaryValue,
      primaryDelta,
      secondaryDelta,
      failureRatePercent,
      pointX: selected.x,
      relatedEvents: this.relatedEventsForBucket(selected.bucketStart, kind),
    };
  }

  private resolveTimelinePoint(
    points: TimelinePoint[],
    selectedIndex: number | null,
  ): TimelinePoint | null {
    if (!points.length) {
      return null;
    }
    const fallbackIndex = points.length - 1;
    const targetIndex =
      selectedIndex === null || selectedIndex < 0 || selectedIndex >= points.length
        ? fallbackIndex
        : selectedIndex;
    let current = 0;
    let fallback: TimelinePoint | null = null;
    for (const point of points) {
      fallback = point;
      if (current === targetIndex) {
        return point;
      }
      current += 1;
    }
    return fallback;
  }

  private relatedEventsForBucket(
    bucketStart: string,
    kind: 'ingest' | 'osv',
  ): TimelineRelatedEvent[] {
    const start = Date.parse(bucketStart);
    if (Number.isNaN(start)) {
      return [];
    }
    const end = start + this.bucketDurationMs();
    const filtered = this.recentFailures().filter((row) => {
      const timestamp = Date.parse(row.timestamp);
      if (Number.isNaN(timestamp) || timestamp < start || timestamp >= end) {
        return false;
      }
      const isSource = this.isSourceEvent(row);
      return kind === 'osv' ? isSource : !isSource;
    });
    filtered.sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
    return filtered.slice(0, 4).map((row) => ({
      timestamp: row.timestamp,
      component: row.component,
      summary: row.summary,
      status: row.status.toUpperCase(),
    }));
  }

  private isSourceEvent(row: SecurityPostureFailure): boolean {
    const component = row.component.trim().toLowerCase();
    const summary = row.summary.trim().toLowerCase();
    return component.startsWith('source_sync') || component.includes('osv') || summary.includes('osv');
  }

  private bucketDurationMs(): number {
    return 24 * 60 * 60 * 1000;
  }

  private buildTimelineTooltip(
    chart: TimelineChart,
    hoveredIndex: number | null,
    selectedIndex: number | null,
    primaryLabel: string,
    secondaryLabel: string,
  ): TimelineTooltip | null {
    const targetIndex = hoveredIndex ?? selectedIndex;
    if (targetIndex === null) {
      return null;
    }
    const point = this.resolveTimelinePoint(chart.points, targetIndex);
    if (!point) {
      return null;
    }
    const leftPercent = Math.max(
      8,
      Math.min(92, (point.x / TIMELINE_VIEWBOX_WIDTH) * 100),
    );
    const anchorY = Math.min(point.primaryY, point.secondaryY);
    const topPercent = Math.max(
      6,
      Math.min(84, (anchorY / TIMELINE_VIEWBOX_HEIGHT) * 100 - 2),
    );
    return {
      leftPercent,
      topPercent,
      timestampLabel: this.formatTimelineTimestamp(point.bucketStart),
      primaryLabel,
      secondaryLabel,
      primaryValue: point.primaryValue,
      secondaryValue: point.secondaryValue,
    };
  }

  private topNDisplay(value: number): string {
    return value <= 0 ? this.topNAllLabel : String(value);
  }

}
