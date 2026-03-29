import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { computed, signal } from '@angular/core';
import { SettingsUser } from '../../data-access/settings.types';
import {
  AdvancedFilterField,
  AdvancedFilterMode,
} from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import {
  SortDirection,
  UserColumnKey,
  createUserFilterMode,
  createUserMultiFilters,
  userColumnKeys,
  userColumns,
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

export class AdminSettingsUsersTableController {
  readonly columns = userColumns;
  readonly lockedColumns: UserColumnKey[] = ['email'];

  readonly columnOrder = signal<UserColumnKey[]>([
    'email',
    'fullName',
    'role',
    'accountType',
    'createdAt',
  ]);
  readonly tablePanelOpen = signal(false);
  readonly filterPanelOpen = signal(false);
  readonly filterVisible = signal<Record<UserColumnKey, boolean>>(
    createFilterVisibilityDefaults(userColumnKeys),
  );
  readonly columnFilters = signal<Record<UserColumnKey, string>>(
    createFilterValuesDefaults(userColumnKeys),
  );
  readonly filterMode = signal<Record<UserColumnKey, AdvancedFilterMode>>(
    createUserFilterMode(),
  );
  readonly multiFilters = signal<Record<UserColumnKey, string[]>>(
    createUserMultiFilters(),
  );
  readonly filterRowVisible = computed(() =>
    Object.values(this.filterVisible()).some(Boolean),
  );
  readonly sortColumn = signal<UserColumnKey | null>('email');
  readonly sortDir = signal<SortDirection>('asc');
  readonly availableColumns = computed(() =>
    availableColumns(this.columns, this.columnOrder()),
  );

  readonly filterOptions = computed<Record<UserColumnKey, string[]>>(() => {
    const rows = this.usersAccessor();
    return {
      id: sortedOptions(rows.map((row) => this.filterValue(row, 'id'))),
      email: sortedOptions(rows.map((row) => this.filterValue(row, 'email'))),
      fullName: sortedOptions(rows.map((row) => this.filterValue(row, 'fullName'))),
      role: sortedOptions(rows.map((row) => this.filterValue(row, 'role'))),
      accountType: sortedOptions(
        rows.map((row) => this.filterValue(row, 'accountType')),
      ),
      createdAt: sortedOptions(rows.map((row) => this.filterValue(row, 'createdAt'))),
    };
  });

  readonly advancedFields = computed<AdvancedFilterField[]>(() => {
    const mode = this.filterMode();
    const filters = this.columnFilters();
    const multi = this.multiFilters();
    const options = this.filterOptions();
    return [
      {
        key: 'id',
        label: 'User ID',
        mode: mode.id,
        value: filters.id,
        options: options.id,
        selected: multi.id,
      },
      {
        key: 'email',
        label: 'Email',
        mode: mode.email,
        value: filters.email,
        options: options.email,
        selected: multi.email,
      },
      {
        key: 'fullName',
        label: 'Full name',
        mode: mode.fullName,
        value: filters.fullName,
        options: options.fullName,
        selected: multi.fullName,
      },
      {
        key: 'role',
        label: 'Role',
        mode: mode.role,
        value: filters.role,
        options: options.role,
        selected: multi.role,
      },
      {
        key: 'accountType',
        label: 'Account type',
        mode: mode.accountType,
        value: filters.accountType,
        options: options.accountType,
        selected: multi.accountType,
      },
      {
        key: 'createdAt',
        label: 'Created',
        mode: mode.createdAt,
        value: filters.createdAt,
        options: options.createdAt,
        selected: multi.createdAt,
      },
    ];
  });

  readonly rows = computed(() => {
    const filters = this.columnFilters();
    const modes = this.filterMode();
    const selected = this.multiFilters();
    const filtered = this.usersAccessor().filter((row) => {
      if (
        !matchesAdvancedFilter(this.filterValue(row, 'id'), modes.id, filters.id, selected.id)
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'email'),
          modes.email,
          filters.email,
          selected.email,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'fullName'),
          modes.fullName,
          filters.fullName,
          selected.fullName,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'role'),
          modes.role,
          filters.role,
          selected.role,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'accountType'),
          modes.accountType,
          filters.accountType,
          selected.accountType,
        )
      ) {
        return false;
      }
      if (
        !matchesAdvancedFilter(
          this.filterValue(row, 'createdAt'),
          modes.createdAt,
          filters.createdAt,
          selected.createdAt,
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

  constructor(private readonly usersAccessor: () => SettingsUser[]) {}

  toggleTablePanel(): void {
    this.tablePanelOpen.update((value) => !value);
  }

  toggleExtendedFilters(): void {
    this.filterPanelOpen.update((value) => !value);
  }

  setFilterMode(key: string, mode: AdvancedFilterMode): void {
    if (!isColumnKey(key, userColumnKeys)) {
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
    if (!isColumnKey(key, userColumnKeys)) {
      return;
    }
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  setMultiFilter(key: string, values: string[]): void {
    if (!isColumnKey(key, userColumnKeys)) {
      return;
    }
    this.multiFilters.update((state) => ({ ...state, [key]: values }));
  }

  clearFilters(): void {
    this.columnFilters.set(createFilterValuesDefaults(userColumnKeys));
    this.filterMode.set(createUserFilterMode());
    this.multiFilters.set(createUserMultiFilters());
  }

  dropColumn(event: CdkDragDrop<string[]>): void {
    const next = [...this.columnOrder()];
    moveItemInArray(next, event.previousIndex, event.currentIndex);
    this.columnOrder.set(next);
  }

  removeColumn(value: string): void {
    if (!isColumnKey(value, userColumnKeys) || this.lockedColumns.includes(value)) {
      return;
    }
    const next = this.columnOrder().filter((item) => item !== value);
    if (next.length < 1) {
      return;
    }
    this.columnOrder.set(next);
  }

  addColumn(value: string): void {
    if (!isColumnKey(value, userColumnKeys) || this.columnOrder().includes(value)) {
      return;
    }
    this.columnOrder.set([...this.columnOrder(), value]);
  }

  toggleFilter(key: string, event: Event): void {
    event.stopPropagation();
    if (!isColumnKey(key, userColumnKeys)) {
      return;
    }
    this.filterVisible.update((state) => {
      switch (key) {
        case 'id':
          return { ...state, id: !state.id };
        case 'email':
          return { ...state, email: !state.email };
        case 'fullName':
          return { ...state, fullName: !state.fullName };
        case 'role':
          return { ...state, role: !state.role };
        case 'accountType':
          return { ...state, accountType: !state.accountType };
        case 'createdAt':
          return { ...state, createdAt: !state.createdAt };
      }
    });
  }

  setColumnFilter(key: string, event: Event): void {
    if (!isColumnKey(key, userColumnKeys)) {
      return;
    }
    const target = event.target as HTMLInputElement | null;
    const value = target?.value ?? '';
    this.filterMode.update((state) => ({ ...state, [key]: 'contains' }));
    this.multiFilters.update((state) => ({ ...state, [key]: [] }));
    this.columnFilters.update((state) => ({ ...state, [key]: value }));
  }

  toggleSort(key: string): void {
    if (!isColumnKey(key, userColumnKeys)) {
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

  value(row: SettingsUser, key: string): string {
    switch (key) {
      case 'id':
        return row.id;
      case 'email':
        return row.email;
      case 'fullName':
        return row.fullName?.trim() || '-';
      case 'role':
        return row.role;
      case 'accountType':
        return row.accountType;
      case 'createdAt':
        return formatDate(row.createdAt);
      default:
        return '-';
    }
  }

  isServiceAccount(row: SettingsUser): boolean {
    return row.accountType === 'SERVICE_ACCOUNT';
  }

  private filterValue(row: SettingsUser, key: UserColumnKey): string {
    if (key === 'createdAt') {
      return formatDate(row.createdAt);
    }
    return this.value(row, key);
  }

  private sortValue(row: SettingsUser, key: UserColumnKey): string | number {
    if (key === 'createdAt') {
      return timestampValue(row.createdAt);
    }
    return this.value(row, key).toLowerCase();
  }
}
