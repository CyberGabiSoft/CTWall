export interface ColumnDefinition<TKey extends string = string, TFilterKey extends string = TKey> {
  key: TKey;
  label: string;
  sortKey: TKey;
  filterKey: TFilterKey;
  className?: string;
}

export type SortDirection = 'asc' | 'desc';

export interface DataTableRowContext<T = unknown> {
  $implicit: T;
  columns: ColumnDefinition[];
  index: number;
  colspan: number;
}
