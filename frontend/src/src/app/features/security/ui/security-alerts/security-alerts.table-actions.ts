import { CdkDragDrop } from '@angular/cdk/drag-drop';
import { WritableSignal } from '@angular/core';
import { AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import {
  addColumnToOrder,
  applyFilterModeChange,
  buildBooleanRecord,
  buildModeRecord,
  buildMultiRecord,
  buildStringRecord,
  moveColumnOrder,
  nextPageIndex,
  normalizePageSize,
  prevPageIndex,
  removeColumnFromOrder,
  setRecordValue,
  setRecordValueFromEvent,
  togglePanelState,
  toggleRecordBoolean,
  toggleSortState,
  SortDirection,
} from './security-alerts.table-state';

export interface SecurityAlertsTableBindings {
  keys: readonly string[];
  lockedColumns: readonly string[];
  tablePanelOpen: WritableSignal<boolean>;
  filterPanelOpen: WritableSignal<boolean>;
  columnOrder: WritableSignal<string[]>;
  filterVisible: WritableSignal<Record<string, boolean>>;
  columnFilters: WritableSignal<Record<string, string>>;
  filterMode: WritableSignal<Record<string, AdvancedFilterMode>>;
  multiFilters: WritableSignal<Record<string, string[]>>;
  sortColumn: WritableSignal<string | null>;
  sortDir: WritableSignal<SortDirection>;
  pageSize: WritableSignal<number>;
  pageIndex: WritableSignal<number>;
}

export function toggleTablePanel(bindings: SecurityAlertsTableBindings): void {
  bindings.tablePanelOpen.update(togglePanelState);
}

export function toggleFilterPanel(bindings: SecurityAlertsTableBindings): void {
  bindings.filterPanelOpen.update(togglePanelState);
}

export function dropColumn(bindings: SecurityAlertsTableBindings, event: CdkDragDrop<string[]>): void {
  bindings.columnOrder.set(
    moveColumnOrder(bindings.columnOrder(), event.previousIndex, event.currentIndex)
  );
}

export function removeColumn(bindings: SecurityAlertsTableBindings, key: string): void {
  bindings.columnOrder.set(
    removeColumnFromOrder(bindings.columnOrder(), key, bindings.lockedColumns)
  );
}

export function addColumn(bindings: SecurityAlertsTableBindings, key: string): void {
  bindings.columnOrder.set(addColumnToOrder(bindings.columnOrder(), key));
}

export function setFilterMode(
  bindings: SecurityAlertsTableBindings,
  key: string,
  mode: AdvancedFilterMode
): void {
  const next = applyFilterModeChange(
    bindings.filterMode(),
    bindings.columnFilters(),
    bindings.multiFilters(),
    key,
    mode
  );
  bindings.filterMode.set(next.modes);
  bindings.columnFilters.set(next.values);
  bindings.multiFilters.set(next.multi);
}

export function setFilterValue(
  bindings: SecurityAlertsTableBindings,
  key: string,
  value: string
): void {
  bindings.columnFilters.update((state) => setRecordValue(state, key, value ?? ''));
}

export function setMultiFilter(
  bindings: SecurityAlertsTableBindings,
  key: string,
  values: string[]
): void {
  bindings.multiFilters.update((state) => setRecordValue(state, key, values ?? []));
}

export function clearFilters(bindings: SecurityAlertsTableBindings): void {
  bindings.columnFilters.set(buildStringRecord(bindings.keys));
  bindings.multiFilters.set(buildMultiRecord(bindings.keys));
  bindings.filterVisible.set(buildBooleanRecord(bindings.keys));
  bindings.filterMode.set(buildModeRecord(bindings.keys, 'contains'));
}

export function toggleColumnFilter(
  bindings: SecurityAlertsTableBindings,
  payload: { key: string; event: Event }
): void {
  payload.event.stopPropagation();
  bindings.filterVisible.update((state) => toggleRecordBoolean(state, payload.key));
}

export function setColumnFilter(
  bindings: SecurityAlertsTableBindings,
  payload: { key: string; event: Event }
): void {
  bindings.columnFilters.update((state) => setRecordValueFromEvent(state, payload.key, payload.event));
}

export function toggleSort(bindings: SecurityAlertsTableBindings, key: string): void {
  const next = toggleSortState(bindings.sortColumn(), bindings.sortDir(), key);
  bindings.sortColumn.set(next.column);
  bindings.sortDir.set(next.direction);
}

export function setPageSize(bindings: SecurityAlertsTableBindings, size: number): void {
  bindings.pageSize.set(normalizePageSize(size, 50));
  bindings.pageIndex.set(0);
}

export function prevPage(bindings: SecurityAlertsTableBindings): void {
  bindings.pageIndex.update(prevPageIndex);
}

export function nextPage(bindings: SecurityAlertsTableBindings, totalPages: number): void {
  bindings.pageIndex.update((current) => nextPageIndex(current, totalPages));
}
