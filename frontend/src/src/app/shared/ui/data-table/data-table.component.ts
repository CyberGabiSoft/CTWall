import { CommonModule } from '@angular/common';
import { DragDropModule, CdkDragDrop } from '@angular/cdk/drag-drop';
import { MatAutocompleteModule } from '@angular/material/autocomplete';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatMenuModule } from '@angular/material/menu';
import { MatOptionModule } from '@angular/material/core';
import { MatSelectModule } from '@angular/material/select';
import {
  AfterViewInit,
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  OnChanges,
  OnDestroy,
  OnInit,
  SimpleChanges,
  TemplateRef,
  ViewChild,
  computed,
  input,
  output,
  signal
} from '@angular/core';
import { Download, Filter, GripVertical, LucideAngularModule, Table, X } from 'lucide-angular';
import { ColumnDefinition, DataTableRowContext, SortDirection } from './data-table.types';
import { DataTableExpandedDetailItem } from './data-table-expanded-details.component';
import { LoadingIndicatorComponent } from '../loading-indicator/loading-indicator.component';
import { getOwnValue, isSafeObjectKey } from '../../utils/safe-object';
import {
  exportTableToCsv,
  exportTableToPdf,
  exportTableToXlsx,
  TableExportFormat
} from '../../utils/table-export';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

type RowKey = string | number;
type TableColumnWithMeta = ColumnDefinition & { source?: 'base' | 'detail' };

const detailColumnPrefix = '__detail__:';
const normalizedKeyPattern = /[^a-z0-9]+/g;

@Component({
  selector: 'app-data-table',
  imports: [
    CommonModule,
    DragDropModule,
    MatAutocompleteModule,
    MatButtonModule,
    MatChipsModule,
    MatFormFieldModule,
    MatInputModule,
    MatMenuModule,
    MatOptionModule,
    MatSelectModule,
    LucideAngularModule,
    LoadingIndicatorComponent
  ],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './data-table.component.html',
  styleUrl: './data-table.component.scss'
})
export class DataTableComponent implements OnInit, OnChanges, AfterViewInit, OnDestroy {
  private static readonly overflowTooltipManagedFlag = '1';
  @ViewChild('tableScroll') private tableScrollRef?: ElementRef<HTMLElement>;

  protected readonly Table = Table;
  protected readonly Filter = Filter;
  protected readonly Download = Download;
  protected readonly GripVertical = GripVertical;
  protected readonly X = X;

  readonly columns = input.required<ColumnDefinition[]>();
  readonly columnOrder = input<string[]>([]);
  readonly columnQuery = input('');
  readonly availableColumns = input<ColumnDefinition[]>([]);
  readonly tablePanelOpen = input(false);
  readonly showTablePanel = input(true);
  readonly lockedColumns = input<string[]>([]);
  readonly showFilterToggle = input(false);
  readonly filterRowVisible = input(false);
  readonly filterVisible = input<Record<string, boolean>>({});
  readonly columnFilters = input<Record<string, string | undefined>>({});
  readonly enableSorting = input(false);
  readonly sortColumn = input<string | null>(null);
  readonly sortDir = input<SortDirection | ''>('');
  readonly rows = input<unknown[]>([]);
  readonly status = input<'loading' | 'error' | 'loaded'>('loaded');
  readonly loadingMessage = input('Loading...');
  readonly errorMessage = input('Failed to load data.');
  readonly emptyMessage = input('No data found.');
  readonly showActionsColumn = input(false);
  readonly tableClass = input('');
  readonly pageSizeOptions = input<number[]>([]);
  readonly pageSize = input(0);
  readonly pageIndex = input(0);
  readonly totalPages = input(1);
  readonly paginationEnabled = input(true);
  readonly autoFitColumns = input(true);
  readonly autoFitMinColumnWidth = input(184);
  readonly autoFitMinVisibleColumns = input(5);
  readonly autoFitReservedWidth = input(88);
  readonly toolbarTemplate = input<TemplateRef<unknown> | null>(null);
  readonly panelTemplate = input<TemplateRef<unknown> | null>(null);
  readonly rowTemplate = input<TemplateRef<DataTableRowContext> | null>(null);
  readonly rowContentTemplate = input<TemplateRef<DataTableRowContext> | null>(null);
  readonly expandedRowTemplate = input<TemplateRef<DataTableRowContext> | null>(null);
  readonly expandedDetails = input<((row: unknown) => ReadonlyArray<DataTableExpandedDetailItem>) | null>(
    null
  );
  readonly actionsTemplate = input<TemplateRef<DataTableRowContext> | null>(null);
  readonly expandable = input(false);
  readonly expandedRowIds = input<ReadonlySet<RowKey> | RowKey[]>([]);
  readonly rowIdKey = input<string | null>(null);
  readonly rowValue = input<((row: unknown, columnKey: string) => string) | null>(null);
  readonly trackByKey = input<string | null>(null);

  // Export
  readonly exportEnabled = input(true);
  readonly exportFilenameBase = input('ctwall_export');
  readonly exportRows = input<unknown[] | null>(null); // optional unpaged + fully filtered dataset
  readonly exportProvider = input<(() => Promise<unknown[]>) | null>(null); // optional async provider for server-paged tables
  readonly exportValue = input<((row: unknown, columnKey: string) => string) | null>(null);

  // Optional "limited preview" mode (e.g. show first N rows + "Load all" action).
  readonly limitedTotal = input<number | null>(null);
  readonly limitedShown = input<number | null>(null);
  readonly limitedActionLabel = input('Load all');
  readonly limitedActionDisabled = input(false);
  readonly loadAllRequested = output<void>();

  readonly toggleTablePanel = output<void>();
  readonly dropColumn = output<CdkDragDrop<string[]>>();
  readonly removeColumn = output<string>();
  readonly addColumn = output<string>();
  readonly setColumnQuery = output<Event>();
  readonly toggleFilter = output<{ key: string; event: Event }>();
  readonly setColumnFilter = output<{ key: string; event: Event }>();
  readonly toggleSort = output<string>();
  readonly setPageSize = output<number>();
  readonly prevPage = output<void>();
  readonly nextPage = output<void>();
  readonly rowToggle = output<RowKey>();

  private readonly viewportWidth = signal(0);
  private readonly initialOrderSignature = signal<string | null>(null);
  private readonly selectedDetailColumnKeys = signal<string[]>([]);
  private resizeObserver: ResizeObserver | null = null;

  readonly configuredBaseColumns = computed(() => {
    const order = this.columnOrder();
    const definitions = this.columns();
    if (order.length === 0) {
      return definitions;
    }
    const byKey = new Map(definitions.map((column) => [column.key, column]));
    return order
      .map((key) => byKey.get(key))
      .filter((column): column is ColumnDefinition => !!column);
  });

  readonly detailColumns = computed<TableColumnWithMeta[]>(() => {
    if (!this.expandable() && !this.expandedDetails()) {
      return [];
    }
    const byKey = new Map<string, TableColumnWithMeta>();
    for (const row of this.detailRowsForColumns()) {
      const items = this.detailItems(row);
      for (const item of items) {
        const detailKey = this.resolveDetailKey(item);
        if (!detailKey || byKey.has(detailKey)) {
          continue;
        }
        const label = (item.label ?? '').trim();
        byKey.set(detailKey, {
          key: detailKey,
          label: label || this.detailColumnLabelFromKey(detailKey),
          sortKey: '',
          filterKey: '',
          className: item.mono === true ? 'mono' : undefined,
          source: 'detail'
        });
      }
    }
    return Array.from(byKey.values());
  });

  readonly selectedDetailColumns = computed<TableColumnWithMeta[]>(() => {
    const byKey = new Map(this.detailColumns().map((column) => [column.key, column]));
    return this.selectedDetailColumnKeys()
      .map((key) => byKey.get(key))
      .filter((column): column is TableColumnWithMeta => !!column);
  });

  readonly selectableColumns = computed<ColumnDefinition[]>(() => {
    const selected = new Set([
      ...this.columnOrder(),
      ...this.selectedDetailColumnKeys()
    ]);
    const base = this.availableColumns().filter((column) => !selected.has(column.key));
    const details = this.detailColumns().filter((column) => !selected.has(column.key));
    return [...base, ...details];
  });

  readonly hasDetailColumnSelection = computed(() => this.selectedDetailColumns().length > 0);

  readonly hasColumnCustomization = computed(() => {
    const initial = this.initialOrderSignature();
    if (!initial) {
      return false;
    }
    const current = this.configuredBaseColumns()
      .map((column) => column.key)
      .join('|');
    return current !== initial || this.hasDetailColumnSelection();
  });

  readonly shouldAutoFitColumns = computed(() => {
    if (!this.autoFitColumns()) {
      return false;
    }
    if (this.hasColumnCustomization()) {
      return false;
    }
    if (this.selectableColumns().length === 0) {
      return false;
    }
    return this.viewportWidth() > 0;
  });

  readonly autoFitVisibleLimit = computed(() => {
    const width = this.viewportWidth();
    if (width <= 0) {
      return Number.POSITIVE_INFINITY;
    }
    const minColumnWidth = Math.max(140, this.autoFitMinColumnWidth());
    const minVisibleColumns = Math.max(1, this.autoFitMinVisibleColumns());
    const reservedWidth = Math.max(0, this.autoFitReservedWidth()) + (this.showActionsColumn() ? 64 : 0);
    const estimate = Math.floor((width - reservedWidth) / minColumnWidth);
    return Math.max(minVisibleColumns, estimate);
  });

  readonly orderedBaseColumns = computed(() => {
    const all = this.configuredBaseColumns();
    if (!this.shouldAutoFitColumns()) {
      return all;
    }
    const limit = this.autoFitVisibleLimit();
    if (all.length <= limit) {
      return all;
    }
    return all.slice(0, limit);
  });

  readonly orderedColumns = computed<TableColumnWithMeta[]>(() => [
    ...this.orderedBaseColumns(),
    ...this.selectedDetailColumns()
  ]);

  readonly autoFitHiddenCount = computed(() => {
    if (!this.shouldAutoFitColumns()) {
      return 0;
    }
    return Math.max(0, this.configuredBaseColumns().length - this.orderedBaseColumns().length);
  });

  readonly tableOptionsHint = computed(() => {
    const hidden = this.autoFitHiddenCount();
    if (hidden <= 0) {
      return '';
    }
    return `Viewport mode: showing ${this.orderedBaseColumns().length} of ${this.configuredBaseColumns().length} columns. Change columns to switch to full-width scrolling mode.`;
  });

  readonly colSpan = computed(() => this.orderedColumns().length + (this.showActionsColumn() ? 1 : 0));

  readonly showToolbar = computed(
    () => Boolean(this.toolbarTemplate()) || this.showTablePanel() || this.exportEnabled()
  );

  readonly exporting = signal(false);

  readonly limitedShownValue = computed(() => {
    const shown = this.limitedShown();
    if (typeof shown === 'number') {
      return shown;
    }
    return this.rows().length;
  });

  readonly showLimitedAction = computed(() => {
    const total = this.limitedTotal();
    if (typeof total !== 'number') {
      return false;
    }
    return total > this.limitedShownValue();
  });

  ngOnInit(): void {
    this.captureInitialOrderIfNeeded();
  }

  ngOnChanges(changes: SimpleChanges): void {
    void changes;
    this.captureInitialOrderIfNeeded();
  }

  ngAfterViewInit(): void {
    const element = this.tableScrollRef?.nativeElement;
    if (!element) {
      return;
    }
    this.syncViewportWidth(element);
    if (typeof ResizeObserver === 'undefined') {
      return;
    }
    this.resizeObserver = new ResizeObserver((entries) => {
      const target = entries[0]?.target;
      if (target instanceof HTMLElement) {
        this.syncViewportWidth(target);
      }
    });
    this.resizeObserver.observe(element);
  }

  ngOnDestroy(): void {
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
  }

  columnClass(column: ColumnDefinition): string {
    const parts: string[] = [];
    if (this.enableSorting() && column.sortKey && !this.isDetailColumnKey(column.key)) {
      parts.push('sortable');
    }
    if (column.className) {
      parts.push(column.className);
    }
    return parts.join(' ');
  }

  columnLabel(key: string): string {
    return (
      this.columns().find((column) => column.key === key)?.label ??
      this.detailColumns().find((column) => column.key === key)?.label ??
      key
    );
  }

  sortIndicator(column: ColumnDefinition): string {
    if (this.isDetailColumnKey(column.key)) {
      return '';
    }
    const active = this.sortColumn();
    const dir = this.sortDir();
    if (!active || !column.sortKey || column.sortKey !== active) {
      return '';
    }
    return dir === 'asc' ? '▲' : '▼';
  }

  trackRow(row: unknown, index: number): unknown {
    const key = this.trackByKey();
    if (key && isRecord(row)) {
      const safeKey = String(key);
      const value = isSafeObjectKey(safeKey) ? getOwnValue(row, safeKey) : undefined;
      return value ?? index;
    }
    return row ?? index;
  }

  rowId(row: unknown, index: number): RowKey {
    const key = this.rowIdKey() ?? this.trackByKey();
    if (key && isRecord(row)) {
      const safeKey = String(key);
      const value = isSafeObjectKey(safeKey) ? getOwnValue(row, safeKey) : undefined;
      if (typeof value === 'string' || typeof value === 'number') {
        return value;
      }
    }
    return index;
  }

  isExpanded(row: unknown, index: number): boolean {
    if (!this.expandable()) {
      return false;
    }
    const ids = this.expandedRowIds();
    const set = Array.isArray(ids) ? new Set(ids) : ids;
    return set.has(this.rowId(row, index));
  }

  onRowClick(row: unknown, index: number, event: Event): void {
    if (!this.expandable()) {
      return;
    }
    event.stopPropagation();
    this.rowToggle.emit(this.rowId(row, index));
  }

  onBodyPointerMove(event: PointerEvent): void {
    this.syncOverflowTooltipFromEvent(event);
  }

  onBodyFocusIn(event: FocusEvent): void {
    this.syncOverflowTooltipFromEvent(event);
  }

  private syncOverflowTooltipFromEvent(event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    const cell = target.closest('tbody td');
    if (!(cell instanceof HTMLElement)) {
      return;
    }
    this.syncOverflowTooltip(cell);
  }

  cellValue(row: unknown, columnKey: string): string {
    if (this.isDetailColumnKey(columnKey)) {
      return this.detailValue(row, columnKey);
    }
    const resolver = this.rowValue();
    if (resolver) {
      const value = resolver(row, columnKey);
      if (value !== undefined && value !== null && value !== '') {
        return value;
      }
    }
    return this.rawValue(row, columnKey) || '-';
  }

  onAddColumn(value: string | null | undefined): void {
    const trimmed = (value ?? '').trim();
    if (!trimmed) {
      return;
    }
    if (this.isDetailColumnKey(trimmed)) {
      if (this.selectedDetailColumnKeys().includes(trimmed)) {
        return;
      }
      this.selectedDetailColumnKeys.set([...this.selectedDetailColumnKeys(), trimmed]);
      return;
    }
    this.addColumn.emit(trimmed);
  }

  removeColumnFromPanel(key: string): void {
    if (this.isDetailColumnKey(key)) {
      this.selectedDetailColumnKeys.set(
        this.selectedDetailColumnKeys().filter((selected) => selected !== key)
      );
      return;
    }
    this.removeColumn.emit(key);
  }

  onToggleFilter(key: string, event: Event): void {
    this.toggleFilter.emit({ key, event });
  }

  onSetColumnFilter(key: string, event: Event): void {
    this.setColumnFilter.emit({ key, event });
  }

  detailColumnLabel(key: string): string {
    return this.detailColumns().find((column) => column.key === key)?.label ?? key;
  }

  private detailRowsForColumns(): unknown[] {
    const exportedRows = this.exportRows();
    if (Array.isArray(exportedRows) && exportedRows.length > 0) {
      return exportedRows;
    }
    return this.rows();
  }

  private detailItems(row: unknown): ReadonlyArray<DataTableExpandedDetailItem> {
    const provider = this.expandedDetails();
    if (provider) {
      return provider(row) ?? [];
    }
    if (!isRecord(row)) {
      return [];
    }
    return Object.entries(row).map(([key, value]) => ({
      key,
      label: this.humanizeLabel(key),
      value: this.serializeValue(value),
      copyValue: this.serializeValue(value),
      mono: typeof value === 'string' && this.looksLikeIdentifier(value)
    }));
  }

  private resolveDetailKey(item: DataTableExpandedDetailItem): string {
    const raw = (item.key ?? item.label ?? '').trim();
    if (!raw) {
      return '';
    }
    const normalized = raw
      .toLowerCase()
      .replace(normalizedKeyPattern, '_')
      .replace(/^_+|_+$/g, '');
    if (!normalized) {
      return '';
    }
    return `${detailColumnPrefix}${normalized}`;
  }

  private detailColumnLabelFromKey(key: string): string {
    const source = key.startsWith(detailColumnPrefix) ? key.slice(detailColumnPrefix.length) : key;
    return this.humanizeLabel(source);
  }

  private detailValue(row: unknown, detailColumnKey: string): string {
    const items = this.detailItems(row);
    const byKey = new Map<string, string>();
    for (const item of items) {
      const key = this.resolveDetailKey(item);
      if (!key) {
        continue;
      }
      byKey.set(key, item.value ?? '');
    }
    return byKey.get(detailColumnKey) ?? '';
  }

  private isDetailColumnKey(columnKey: string): boolean {
    return columnKey.startsWith(detailColumnPrefix);
  }

  private rawValue(row: unknown, key: string): string {
    return this.serializeValue(this.readRecordValue(row, key));
  }

  private serializeValue(value: unknown): string {
    if (value === null || value === undefined) {
      return '';
    }
    if (typeof value === 'string') {
      return value;
    }
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
      return String(value);
    }
    if (Array.isArray(value)) {
      if (value.length === 0) {
        return '';
      }
      return value.map((entry) => this.serializeValue(entry)).filter((entry) => entry.length > 0).join(', ');
    }
    try {
      return JSON.stringify(value);
    } catch {
      return '';
    }
  }

  private humanizeLabel(raw: string): string {
    const normalized = raw
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/[._-]+/g, ' ')
      .trim();
    if (!normalized) {
      return raw;
    }
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }

  private looksLikeIdentifier(value: string): boolean {
    return value.includes(':') || value.includes('/') || value.length >= 24;
  }

  private readRecordValue(row: unknown, key: string): unknown {
    if (!isRecord(row)) {
      return undefined;
    }
    const safeKey = String(key);
    if (!isSafeObjectKey(safeKey)) {
      return undefined;
    }
    return getOwnValue(row, safeKey);
  }

  private derivedExportValue(row: unknown, key: string): string {
    const normalized = key.trim().toLowerCase();
    if (!normalized || !isRecord(row)) {
      return '';
    }

    for (const alias of this.aliasesForColumn(normalized)) {
      const value = this.serializeValue(this.readRecordValue(row, alias));
      if (value !== '') {
        return value;
      }
    }

    // Global fallback for Malware Summary style rows where displayed columns are derived.
    if (normalized === 'malware') {
      const malwareFlag = this.readRecordValue(row, 'isMalware');
      if (typeof malwareFlag === 'boolean') {
        return malwareFlag ? 'MALWARE' : 'CLEAN';
      }
      const status = this.serializeValue(this.readRecordValue(row, 'findingsStatus')).toLowerCase();
      if (status && status !== 'loaded') {
        return 'UNKNOWN';
      }
      const findings = this.readRecordValue(row, 'findingsCount');
      if (typeof findings === 'number') {
        return findings > 0 ? 'MALWARE' : 'CLEAN';
      }
    }

    if (normalized === 'findings') {
      const status = this.serializeValue(this.readRecordValue(row, 'findingsStatus')).toLowerCase();
      if (status === 'loading') {
        return '-';
      }
      if (status === 'error') {
        return 'Error';
      }
      const findings = this.readRecordValue(row, 'findingsCount');
      if (typeof findings === 'number') {
        return String(findings);
      }
    }

    return '';
  }

  private aliasesForColumn(columnKey: string): string[] {
    const predefined = new Map<string, string[]>([
      ['product', ['productName', 'productId']],
      ['scope', ['scopeName', 'scopeId']],
      ['test', ['testName', 'testId']],
      ['when', ['timestamp', 'createdAt', 'updatedAt', 'occurredAt']],
      ['findings', ['findingsCount', 'findingsStatus']],
      ['active', ['isActive', 'revisionIsActive']]
    ]);

    return [
      ...(predefined.get(columnKey) ?? []),
      `${columnKey}Name`,
      `${columnKey}Id`,
      `${columnKey}Count`,
      `${columnKey}Status`,
      `${columnKey}At`
    ];
  }

  private exportColumns(format: TableExportFormat): Array<{ key: string; label: string }> {
    if (format === 'pdf') {
      return this.orderedColumns().map((column) => ({ key: column.key, label: column.label }));
    }
    const all = [...this.configuredBaseColumns(), ...this.detailColumns()];
    const seen = new Set<string>();
    const out: Array<{ key: string; label: string }> = [];
    for (const column of all) {
      if (seen.has(column.key)) {
        continue;
      }
      seen.add(column.key);
      out.push({ key: column.key, label: column.label });
    }
    return out;
  }

  private exportValueForCell(row: unknown, key: string): string {
    if (this.isDetailColumnKey(key)) {
      return this.detailValue(row, key);
    }
    const fn = this.exportValue() ?? this.rowValue();
    if (fn) {
      const value = fn(row, key);
      if (value !== undefined && value !== null && value !== '') {
        return value;
      }
    }
    const direct = this.rawValue(row, key);
    if (direct !== '') {
      return direct;
    }
    const derived = this.derivedExportValue(row, key);
    if (derived !== '') {
      return derived;
    }
    return this.cellValue(row, key);
  }

  private async resolveExportRows(): Promise<unknown[]> {
    const provider = this.exportProvider();
    if (provider) {
      return provider();
    }
    const rows = this.exportRows();
    if (Array.isArray(rows)) {
      return rows;
    }
    return this.rows();
  }

  async export(format: TableExportFormat): Promise<void> {
    if (this.exporting()) {
      return;
    }
    this.exporting.set(true);
    try {
      const rows = await this.resolveExportRows();
      const columns = this.exportColumns(format);
      const filenameBase = this.exportFilenameBase().trim() || 'ctwall_export';
      const valueForCell = (row: unknown, columnKey: string) => this.exportValueForCell(row, columnKey);

      if (format === 'csv') {
        await exportTableToCsv({ filenameBase, columns, rows, valueForCell });
      } else if (format === 'xlsx') {
        await exportTableToXlsx({ filenameBase, columns, rows, valueForCell });
      } else {
        await exportTableToPdf({ filenameBase, title: filenameBase, columns, rows, valueForCell });
      }
    } finally {
      this.exporting.set(false);
    }
  }

  private syncViewportWidth(element: HTMLElement): void {
    const width = Math.max(0, Math.floor(element.clientWidth));
    this.viewportWidth.set(width);
  }

  private captureInitialOrderIfNeeded(): void {
    if (this.initialOrderSignature() !== null) {
      return;
    }
    const signature = this.configuredBaseColumns()
      .map((column) => column.key)
      .join('|');
    if (!signature) {
      return;
    }
    this.initialOrderSignature.set(signature);
  }

  private syncOverflowTooltip(cell: HTMLElement): void {
    if (cell.classList.contains('actions')) {
      this.clearManagedOverflowTooltip(cell);
      return;
    }
    const managed = cell.dataset['ctwOverflowTooltip'] === DataTableComponent.overflowTooltipManagedFlag;
    if (cell.hasAttribute('title') && !managed) {
      return;
    }

    const source = this.findOverflowSource(cell);
    if (!source) {
      this.clearManagedOverflowTooltip(cell);
      return;
    }
    const value = this.normalizeTooltipValue(source.innerText || source.textContent || '');
    if (!value) {
      this.clearManagedOverflowTooltip(cell);
      return;
    }

    cell.setAttribute('title', value);
    cell.dataset['ctwOverflowTooltip'] = DataTableComponent.overflowTooltipManagedFlag;
  }

  private clearManagedOverflowTooltip(cell: HTMLElement): void {
    if (cell.dataset['ctwOverflowTooltip'] !== DataTableComponent.overflowTooltipManagedFlag) {
      return;
    }
    cell.removeAttribute('title');
    delete cell.dataset['ctwOverflowTooltip'];
  }

  private findOverflowSource(cell: HTMLElement): HTMLElement | null {
    if (this.isOverflowing(cell)) {
      return cell;
    }
    const candidates = cell.querySelectorAll<HTMLElement>('span,div,p,a,code');
    for (const candidate of candidates) {
      if (this.isOverflowing(candidate)) {
        return candidate;
      }
    }
    return null;
  }

  private isOverflowing(element: HTMLElement): boolean {
    const overflowX = element.scrollWidth - element.clientWidth > 1;
    const overflowY = element.scrollHeight - element.clientHeight > 1;
    return overflowX || overflowY;
  }

  private normalizeTooltipValue(value: string): string {
    return value.replace(/\s+/g, ' ').trim();
  }
}
