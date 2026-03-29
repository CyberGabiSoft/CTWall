import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { computed, signal } from '@angular/core';
import { AdminConnector } from '../../data-access/settings.types';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import {
  ConnectorColumnKey,
  SortDirection,
  connectorColumnKeys,
  connectorColumns,
  createConnectorFilterMode,
  createConnectorMultiFilters,
} from './admin-settings.tables';
import {
  availableColumns,
  createFilterValuesDefaults,
  createFilterVisibilityDefaults,
  formatDate,
  isColumnKey,
  matchesAdvancedFilter,
  sortRows,
  sortedOptions,
  timestampValue,
} from './admin-settings.utils';

export class AdminSettingsConnectorsTableController {
  readonly columns = connectorColumns;
  readonly lockedColumns: ConnectorColumnKey[] = ['type'];

  readonly columnOrder = signal<ConnectorColumnKey[]>([...connectorColumnKeys]);
  readonly tablePanelOpen = signal(false);
  readonly filterPanelOpen = signal(false);
  readonly filterVisible = signal<Record<ConnectorColumnKey, boolean>>(
    createFilterVisibilityDefaults(connectorColumnKeys),
  );
  readonly columnFilters = signal<Record<ConnectorColumnKey, string>>(
    createFilterValuesDefaults(connectorColumnKeys),
  );
  readonly filterMode = signal<Record<ConnectorColumnKey, AdvancedFilterMode>>(
    createConnectorFilterMode(),
  );
  readonly multiFilters = signal<Record<ConnectorColumnKey, string[]>>(
    createConnectorMultiFilters(),
  );
  readonly filterRowVisible = computed(() =>
    Object.values(this.filterVisible()).some(Boolean),
  );
  readonly sortColumn = signal<ConnectorColumnKey | null>('type');
  readonly sortDir = signal<SortDirection>('asc');
  readonly availableColumns = computed(() =>
    availableColumns(this.columns, this.columnOrder()),
  );

  readonly filterOptions = computed<Record<ConnectorColumnKey, string[]>>(() => {
    const rows = this.connectorsAccessor();
    return {
      type: sortedOptions(rows.map((row) => this.filterValue(row, 'type'))),
      scopeType: sortedOptions(rows.map((row) => this.filterValue(row, 'scopeType'))),
      enabled: sortedOptions(rows.map((row) => this.filterValue(row, 'enabled'))),
      configured: sortedOptions(rows.map((row) => this.filterValue(row, 'configured'))),
      lastTestStatus: sortedOptions(
        rows.map((row) => this.filterValue(row, 'lastTestStatus')),
      ),
      lastTestAt: sortedOptions(rows.map((row) => this.filterValue(row, 'lastTestAt'))),
      updatedAt: sortedOptions(rows.map((row) => this.filterValue(row, 'updatedAt'))),
    };
  });

  readonly advancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.filterMode();
    const filters = this.columnFilters();
    const multi = this.multiFilters();
    const options = this.filterOptions();
    return [
      {
        key: 'type',
        label: 'Type',
        mode: mode.type,
        value: filters.type,
        options: options.type,
        selected: multi.type,
      },
      {
        key: 'scopeType',
        label: 'Scope',
        mode: mode.scopeType,
        value: filters.scopeType,
        options: options.scopeType,
        selected: multi.scopeType,
      },
      {
        key: 'enabled',
        label: 'Enabled',
        mode: mode.enabled,
        value: filters.enabled,
        options: options.enabled,
        selected: multi.enabled,
      },
      {
        key: 'configured',
        label: 'Configured',
        mode: mode.configured,
        value: filters.configured,
        options: options.configured,
        selected: multi.configured,
      },
      {
        key: 'lastTestStatus',
        label: 'Last test',
        mode: mode.lastTestStatus,
        value: filters.lastTestStatus,
        options: options.lastTestStatus,
        selected: multi.lastTestStatus,
      },
      {
        key: 'lastTestAt',
        label: 'Tested at',
        mode: mode.lastTestAt,
        value: filters.lastTestAt,
        options: options.lastTestAt,
        selected: multi.lastTestAt,
      },
      {
        key: 'updatedAt',
        label: 'Updated',
        mode: mode.updatedAt,
        value: filters.updatedAt,
        options: options.updatedAt,
        selected: multi.updatedAt,
      },
    ];
  });

  readonly rows = computed(() => {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = this.connectorsAccessor().filter((row) => {
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'type'),
          modes.type,
          filters.type,
          selected.type,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'scopeType'),
          modes.scopeType,
          filters.scopeType,
          selected.scopeType,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'enabled'),
          modes.enabled,
          filters.enabled,
          selected.enabled,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'configured'),
          modes.configured,
          filters.configured,
          selected.configured,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'lastTestStatus'),
          modes.lastTestStatus,
          filters.lastTestStatus,
          selected.lastTestStatus,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'lastTestAt'),
          modes.lastTestAt,
          filters.lastTestAt,
          selected.lastTestAt,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'updatedAt'),
          modes.updatedAt,
          filters.updatedAt,
          selected.updatedAt,
        )
      ) {
        return false;
      }
      return true;
    });
    return sortRows(filtered, this.sortColumn(), this.sortDir(), (row, key) =>
      this.sortValue(row, key),
    );
  });

  constructor(private readonly connectorsAccessor: () => AdminConnector[]) {}

  toggleTablePanel(): void {
    this.tablePanelOpen.update((value) => !value);
  }

  toggleExtendedFilters(): void {
    this.filterPanelOpen.update((value) => !value);
  }

  setFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    this.filterMode.update((state) => ({ ...state, [key]: mode }));
    if (mode === 'contains') {
      this.multiFilters.update((state) => ({ ...state, [key]: [] }));
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: '' }));
  }

  setFilterValue(key: string, value: string): void {
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setMultiFilter(key: string, values: string[]): void {
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    this.multiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearFilters(): void {
    this.columnFilters.set(createFilterValuesDefaults(connectorColumnKeys));
    this.filterMode.set(createConnectorFilterMode());
    this.multiFilters.set(createConnectorMultiFilters());
  }

  dropColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.columnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.columnOrder.set(next);
  }

  removeColumn(value: string): void {
    if (!isColumnKey(value, connectorColumnKeys) || this.lockedColumns.includes(value)) {
      return;
    }
    const next = this.columnOrder().filter((item) => item !== value);
    if (next.length < 1) {
      return;
    }
    this.columnOrder.set(next);
  }

  addColumn(value: string): void {
    if (!isColumnKey(value, connectorColumnKeys) || this.columnOrder().includes(value)) {
      return;
    }
    this.columnOrder.set([...this.columnOrder(), value]);
  }

  toggleFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    this.filterVisible.update((state) => {
      switch (key) {
        case 'type':
          return { ...state, type: !state.type };
        case 'scopeType':
          return { ...state, scopeType: !state.scopeType };
        case 'enabled':
          return { ...state, enabled: !state.enabled };
        case 'configured':
          return { ...state, configured: !state.configured };
        case 'lastTestStatus':
          return { ...state, lastTestStatus: !state.lastTestStatus };
        case 'lastTestAt':
          return { ...state, lastTestAt: !state.lastTestAt };
        case 'updatedAt':
          return { ...state, updatedAt: !state.updatedAt };
      }
    });
  }

  setColumnFilter(key: string, event: Event): void {
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.filterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.multiFilters.update((state) => ({ ...state, [key]: [] }));
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  toggleSort(key: string): void {
    if (!isColumnKey(key, connectorColumnKeys)) {
      return;
    }
    const current = this.sortColumn();
    if (current === key) {
      this.sortDir.set(this.sortDir() === 'asc' ? 'desc' : 'asc');
      return;
    }
    this.sortColumn.set(key);
    this.sortDir.set('asc');
  }

  value(row: AdminConnector, key: string): string {
    switch (key) {
      case 'type':
        return (row.type ?? '-').toUpperCase();
      case 'scopeType':
        return row.scopeType ?? '-';
      case 'enabled':
        return row.enabled ? 'Yes' : 'No';
      case 'configured':
        return row.configured ? 'Yes' : 'No';
      case 'lastTestStatus':
        return row.lastTestStatus ?? 'NOT_CONFIGURED';
      case 'lastTestAt':
        return formatDate(row.lastTestAt);
      case 'updatedAt':
        return formatDate(row.updatedAt);
      default:
        return '-';
    }
  }

  private filterValue(row: AdminConnector, key: ConnectorColumnKey): string {
    return this.value(row, key);
  }

  private sortValue(row: AdminConnector, key: ConnectorColumnKey): string | number {
    switch (key) {
      case 'enabled':
        return row.enabled ? 1 : 0;
      case 'configured':
        return row.configured ? 1 : 0;
      case 'lastTestAt':
        return timestampValue(row.lastTestAt);
      case 'updatedAt':
        return timestampValue(row.updatedAt);
      default:
        return this.value(row, key).toLowerCase();
    }
  }
}
