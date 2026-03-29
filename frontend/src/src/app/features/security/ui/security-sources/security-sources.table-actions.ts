import { CdkDragDrop, moveItemInArray } from '@angular/cdk/drag-drop';
import { WritableSignal } from '@angular/core';
import { ColumnDefinition } from '../../../../shared/ui/data-table/data-table.types';
import {
  buildFilterModes,
  buildFilterValues,
  buildFilterVisibility,
  buildMultiFilters,
  FilterMode,
} from '../../../../shared/utils/table-filter-records';
import { SortDirection, setFilterValueFromEvent, setFilterValueFromString, toggleSort, toggleVisibility } from './security-sources.utils';

export interface TableStateBindings {
  filterVisible: WritableSignal<Record<string, boolean>>;
  columnFilters: WritableSignal<Record<string, string>>;
  filterMode: WritableSignal<Record<string, FilterMode>>;
  multiFilters: WritableSignal<Record<string, string[]>>;
  sortColumn: WritableSignal<string | null>;
  sortDir: WritableSignal<SortDirection>;
  pageSize: WritableSignal<number>;
  pageIndex: WritableSignal<number>;
  columnOrder: WritableSignal<string[]>;
  columnQuery: WritableSignal<string>;
}

export function togglePanel(panel: WritableSignal<boolean>): void {
  panel.update((value) => !value);
}

export function applyFilterMode(
  modeState: WritableSignal<Record<string, FilterMode>>,
  filtersState: WritableSignal<Record<string, string>>,
  key: string,
  mode: FilterMode
): void {
  modeState.set({ ...modeState(), [key]: mode });
  if (mode === 'select') {
    filtersState.set({ ...filtersState(), [key]: '' });
  }
}

export function applyMultiFilter(
  multiFiltersState: WritableSignal<Record<string, string[]>>,
  key: string,
  values: string[]
): void {
  multiFiltersState.set({ ...multiFiltersState(), [key]: values });
}

export function applyFilterValue(
  applyMode: (key: string, mode: FilterMode) => void,
  filtersState: WritableSignal<Record<string, string>>,
  key: string,
  value: string
): void {
  applyMode(key, 'contains');
  filtersState.set(setFilterValueFromString(filtersState(), key, value));
}

export function clearTableFilters(
  state: TableStateBindings,
  columns: readonly ColumnDefinition[],
  advancedKeys: readonly string[]
): void {
  state.columnFilters.set(buildFilterValues(columns));
  state.multiFilters.set(buildMultiFilters(advancedKeys));
  state.filterMode.set(buildFilterModes(advancedKeys));
  state.filterVisible.set(buildFilterVisibility(columns));
}

export function setTableColumnQuery(columnQuery: WritableSignal<string>, event: Event): void {
  const target = event.target as HTMLInputElement | null;
  columnQuery.set(target?.value ?? '');
}

export function addTableColumn(columnOrder: WritableSignal<string[]>, columnQuery: WritableSignal<string>, key: string): void {
  if (columnOrder().includes(key)) {
    return;
  }
  columnOrder.set([...columnOrder(), key]);
  columnQuery.set('');
}

export function removeTableColumn(columnOrder: WritableSignal<string[]>, key: string): void {
  columnOrder.set(columnOrder().filter((column) => column !== key));
}

export function dropTableColumn(columnOrder: WritableSignal<string[]>, event: CdkDragDrop<string[]>): void {
  if (event.previousIndex === event.currentIndex) {
    return;
  }
  const next = [...columnOrder()];
  moveItemInArray(next, event.previousIndex, event.currentIndex);
  columnOrder.set(next);
}

export function setTablePageSize(pageSize: WritableSignal<number>, pageIndex: WritableSignal<number>, size: number): void {
  pageSize.set(size);
  pageIndex.set(0);
}

export function prevTablePage(pageIndex: WritableSignal<number>): void {
  const current = pageIndex();
  if (current > 0) {
    pageIndex.set(current - 1);
  }
}

export function nextTablePage(pageIndex: WritableSignal<number>, totalPages: number): void {
  const current = pageIndex();
  if (current + 1 < totalPages) {
    pageIndex.set(current + 1);
  }
}

export function toggleTableFilterVisibility(
  visibleState: WritableSignal<Record<string, boolean>>,
  payload: { key: string; event: Event }
): void {
  payload.event.stopPropagation();
  visibleState.set(toggleVisibility(visibleState(), payload.key));
}

export function setTableColumnFilter(
  applyMode: (key: string, mode: FilterMode) => void,
  filtersState: WritableSignal<Record<string, string>>,
  payload: { key: string; event: Event }
): void {
  applyMode(payload.key, 'contains');
  filtersState.set(setFilterValueFromEvent(filtersState(), payload.key, payload.event));
}

export function toggleTableSortState(
  sortColumn: WritableSignal<string | null>,
  sortDirection: WritableSignal<SortDirection>,
  key: string
): void {
  const next = toggleSort(sortColumn(), sortDirection(), key);
  sortColumn.set(next.column);
  sortDirection.set(next.direction);
}
