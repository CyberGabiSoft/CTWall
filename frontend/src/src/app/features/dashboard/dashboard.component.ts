
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
import { DashboardStore } from './state/dashboard.store';
import {
  DashboardIngestActivity,
  DashboardMalwarePackage,
} from './data-access/dashboard.types';
import { ProjectContextService } from '../projects/data-access/project-context.service';
import { LoadingIndicatorComponent } from '../../shared/ui/loading-indicator/loading-indicator.component';
import { DataTableComponent } from '../../shared/ui/data-table/data-table.component';
import { ColumnDefinition } from '../../shared/ui/data-table/data-table.types';
import { PieChartComponent, PieChartSlice } from '../../shared/ui/pie-chart/pie-chart.component';

const malwarePackageColumns: ColumnDefinition[] = [
  { key: 'purl', label: 'PURL', sortKey: 'purl', filterKey: 'purl', className: 'mono' },
  { key: 'occurrences', label: 'Occurrences', sortKey: 'occurrences', filterKey: 'occurrences' },
  { key: 'lastSeenAt', label: 'Last seen', sortKey: 'lastSeenAt', filterKey: 'lastSeenAt' },
];

const recentIngestColumns: ColumnDefinition[] = [
  { key: 'timestamp', label: 'When', sortKey: 'timestamp', filterKey: 'timestamp' },
  { key: 'target', label: 'Target', sortKey: 'target', filterKey: 'target' },
  { key: 'summary', label: 'Summary', sortKey: 'summary', filterKey: 'summary' },
  { key: 'status', label: 'Status', sortKey: 'status', filterKey: 'status' },
];

const TOP_PIE_PALETTE = [
  '#5ea1ff',
  '#2dd4bf',
  '#a78bfa',
  '#f59e0b',
  '#ef4444',
  '#22c55e',
  '#ec4899',
  '#84cc16',
];

@Component({
  selector: 'app-dashboard',
  imports: [
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatSelectModule,
    LoadingIndicatorComponent,
    DataTableComponent,
    PieChartComponent
],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.scss',
})
export class DashboardComponent implements OnInit {
  private readonly router = inject(Router);
  private readonly projectContext = inject(ProjectContextService);
  readonly store = inject(DashboardStore);

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
  readonly packageColumns = malwarePackageColumns;
  readonly ingestColumns = recentIngestColumns;

  readonly packageColumnOrder = signal(['purl', 'occurrences', 'lastSeenAt']);
  readonly ingestColumnOrder = signal(['timestamp', 'target', 'summary', 'status']);
  readonly selectedTopProductsSliceIndex = signal<number | null>(null);
  readonly selectedTopScopesSliceIndex = signal<number | null>(null);
  readonly selectedTopPackageTypesSliceIndex = signal<number | null>(null);
  readonly selectedTopLicensesSliceIndex = signal<number | null>(null);
  readonly selectedVerdictSliceIndex = signal<number | null>(null);

  readonly kpis = computed(() => this.store.data().kpis);
  readonly data = computed(() => this.store.data());
  readonly selectedProjectName = computed(() => this.projectContext.selectedProjectName());
  readonly verdictDistribution = computed(() => this.store.data().verdictDistribution);
  readonly verdictTotal = computed(() => {
    const verdict = this.verdictDistribution();
    return verdict.malware + verdict.clean + verdict.unknown;
  });
  readonly topProducts = computed(() => this.store.data().topProducts);
  readonly topScopes = computed(() => this.store.data().topScopes);
  readonly topPackageTypes = computed(() => this.store.data().topPackageTypes);
  readonly topLicenses = computed(() => this.store.data().topLicenses);
  readonly topMalwarePackages = computed(() => this.store.data().topMalwarePackages);
  readonly recentIngest = computed(() => this.store.data().recentIngest);
  readonly topProductsTotal = computed(() =>
    this.topProducts().reduce((sum, item) => sum + Math.max(0, item.value), 0),
  );
  readonly topScopesTotal = computed(() =>
    this.topScopes().reduce((sum, item) => sum + Math.max(0, item.value), 0),
  );
  readonly topPackageTypesTotal = computed(() =>
    this.topPackageTypes().reduce((sum, item) => sum + Math.max(0, item.count), 0),
  );
  readonly topLicensesTotal = computed(() =>
    this.topLicenses().reduce((sum, item) => sum + Math.max(0, item.count), 0),
  );
  readonly topNLabel = computed(() => this.topNDisplay(this.data().topN));
  readonly topProductsPieSlices = computed<PieChartSlice[]>(() =>
    this.topProducts().map((item, index) => ({
      id: `product-${index}`,
      label: item.name,
      value: Math.max(0, item.value),
      color: TOP_PIE_PALETTE[index % TOP_PIE_PALETTE.length] ?? 'var(--ctw-primary)',
      tooltipValue: this.formatInteger(item.value),
    })),
  );
  readonly topScopesPieSlices = computed<PieChartSlice[]>(() =>
    this.topScopes().map((item, index) => ({
      id: `scope-${index}`,
      label: item.name,
      value: Math.max(0, item.value),
      color: TOP_PIE_PALETTE[index % TOP_PIE_PALETTE.length] ?? 'var(--ctw-primary)',
      tooltipValue: this.formatInteger(item.value),
    })),
  );
  readonly topPackageTypesPieSlices = computed<PieChartSlice[]>(() =>
    this.topPackageTypes().map((item, index) => ({
      id: `package-type-${index}`,
      label: item.packageType,
      value: Math.max(0, item.count),
      color: TOP_PIE_PALETTE[index % TOP_PIE_PALETTE.length] ?? 'var(--ctw-primary)',
      tooltipValue: this.formatInteger(item.count),
    })),
  );
  readonly topLicensesPieSlices = computed<PieChartSlice[]>(() =>
    this.topLicenses().map((item, index) => ({
      id: `license-${index}`,
      label: item.license,
      value: Math.max(0, item.count),
      color: TOP_PIE_PALETTE[index % TOP_PIE_PALETTE.length] ?? 'var(--ctw-primary)',
      tooltipValue: this.formatInteger(item.count),
    })),
  );
  readonly verdictPieSlices = computed<PieChartSlice[]>(() => {
    const verdict = this.verdictDistribution();
    return [
      {
        id: 'malware',
        label: 'Malware',
        value: Math.max(0, verdict.malware),
        color: 'var(--ctw-danger-text)',
        tooltipValue: this.formatInteger(verdict.malware),
      },
      {
        id: 'clean',
        label: 'Clean',
        value: Math.max(0, verdict.clean),
        color: 'var(--ctw-success-text)',
        tooltipValue: this.formatInteger(verdict.clean),
      },
      {
        id: 'unknown',
        label: 'Unknown',
        value: Math.max(0, verdict.unknown),
        color: 'var(--ctw-warning-text)',
        tooltipValue: this.formatInteger(verdict.unknown),
      },
    ];
  });

  ngOnInit(): void {
    void this.store.ensureFresh();
  }

  async onTopNChange(topN: number): Promise<void> {
    await this.store.setTopN(topN);
  }

  packageRowValue(row: DashboardMalwarePackage, column: string): string {
    if (column === 'occurrences') {
      return this.formatInteger(row.occurrences);
    }
    if (column === 'lastSeenAt') {
      return this.formatRelative(row.lastSeenAt ?? null);
    }
    return row.purl;
  }

  ingestRowValue(row: DashboardIngestActivity, column: string): string {
    if (column === 'timestamp') {
      return this.formatRelative(row.timestamp);
    }
    if (column === 'target') {
      return this.ingestTarget(row);
    }
    if (column === 'summary') {
      return this.ingestSummary(row);
    }
    return this.normalizeStatus(row.status);
  }

  formatInteger(value: number): string {
    return new Intl.NumberFormat().format(value);
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

  openExplorer(): void {
    void this.router.navigate(['/security/explorer']);
  }

  openIngestRow(row: DashboardIngestActivity): void {
    const testId = (row.testId ?? '').trim();
    if (testId) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'tests',
          productId: (row.productId ?? '').trim() || null,
          scopeId: (row.scopeId ?? '').trim() || null,
          testId,
          detail: '1',
        },
      });
      return;
    }
    const scopeId = (row.scopeId ?? '').trim();
    if (scopeId) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'tests',
          productId: (row.productId ?? '').trim() || null,
          scopeId,
        },
      });
      return;
    }
    const productId = (row.productId ?? '').trim();
    if (productId) {
      void this.router.navigate(['/data'], {
        queryParams: {
          section: 'scopes',
          productId,
        },
      });
      return;
    }
    void this.router.navigate(['/data']);
  }

  statusBadgeClass(status: string): string {
    const normalized = this.normalizeStatus(status);
    if (normalized === 'FAILED') {
      return 'badge badge-danger';
    }
    if (normalized === 'COMPLETED') {
      return 'badge badge-ok';
    }
    return 'badge badge-muted';
  }

  normalizeStatus(status: string): string {
    const normalized = status.trim().toUpperCase();
    if (!normalized) {
      return 'UNKNOWN';
    }
    return normalized;
  }

  ingestTarget(item: DashboardIngestActivity): string {
    const parts = [item.productName, item.scopeName, item.testName]
      .map((value) => value.trim())
      .filter(Boolean);
    if (!parts.length) {
      return 'N/A';
    }
    return parts.join(' / ');
  }

  ingestSummary(item: DashboardIngestActivity): string {
    const components = `${this.formatInteger(Math.max(0, item.componentsImported))} components`;
    const stage = item.stage.trim();
    const status = this.normalizeStatus(item.status);
    if (status === 'FAILED' && item.errorMessage) {
      return `${stage || status}: ${item.errorMessage}`;
    }
    if (stage) {
      return `${stage} (${components})`;
    }
    return components;
  }

  topSharePercent(value: number, total: number): string {
    if (total <= 0 || value <= 0) {
      return '0%';
    }
    return `${Math.round((value / total) * 100)}%`;
  }

  onTopProductsSliceSelected(index: number | null): void {
    this.selectedTopProductsSliceIndex.set(index);
  }

  onTopScopesSliceSelected(index: number | null): void {
    this.selectedTopScopesSliceIndex.set(index);
  }

  onTopPackageTypesSliceSelected(index: number | null): void {
    this.selectedTopPackageTypesSliceIndex.set(index);
  }

  onTopLicensesSliceSelected(index: number | null): void {
    this.selectedTopLicensesSliceIndex.set(index);
  }

  onVerdictSliceSelected(index: number | null): void {
    this.selectedVerdictSliceIndex.set(index);
  }

  private topNDisplay(value: number): string {
    return value <= 0 ? this.topNAllLabel : String(value);
  }
}
