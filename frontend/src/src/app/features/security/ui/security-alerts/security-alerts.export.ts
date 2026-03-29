import { AlertsApi, AlertGroupsListQuery, AlertOccurrencesListQuery } from '../../data-access/alerts.api';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import {
  AlertGroupFilterState,
  AlertOccurrenceFilterState,
  applyGroupFiltersAndSort,
  applyOccurrenceFiltersAndSort,
} from './security-alerts.mapper';

const EXPORT_PAGE_SIZE = 200;
const MAX_EXPORT_ROWS = 10_000;

interface PagePayload<T> {
  items?: T[] | null;
  totalPages?: number;
}

async function collectPagedRows<T>(
  fetchPage: (page: number, pageSize: number) => Promise<PagePayload<T>>
): Promise<T[]> {
  const rows: T[] = [];
  let page = 1;
  let totalPages = 1;
  while (page <= totalPages) {
    const payload = await fetchPage(page, EXPORT_PAGE_SIZE);
    const items = payload.items ?? [];
    rows.push(...items);
    totalPages = typeof payload.totalPages === 'number' && payload.totalPages > 0 ? payload.totalPages : totalPages;
    if (rows.length >= MAX_EXPORT_ROWS) {
      break;
    }
    page += 1;
  }
  return rows.slice(0, MAX_EXPORT_ROWS);
}

export async function exportAllGroups(
  api: AlertsApi,
  query: AlertGroupsListQuery,
  filterState: AlertGroupFilterState
): Promise<AlertGroup[]> {
  const rows = await collectPagedRows<AlertGroup>((page, pageSize) =>
    api.listGroups({
      page,
      pageSize,
      severity: query.severity,
      category: query.category,
      type: query.type,
      status: query.status,
      q: query.q,
      from: query.from,
      to: query.to,
    })
  );
  return applyGroupFiltersAndSort(rows, filterState).slice(0, MAX_EXPORT_ROWS);
}

export async function exportAllOccurrences(
  api: AlertsApi,
  query: AlertOccurrencesListQuery,
  filterState: AlertOccurrenceFilterState
): Promise<AlertOccurrence[]> {
  const rows = await collectPagedRows<AlertOccurrence>((page, pageSize) =>
    api.listOccurrences({
      page,
      pageSize,
      groupId: query.groupId,
      severity: query.severity,
      category: query.category,
      type: query.type,
      q: query.q,
      from: query.from,
      to: query.to,
    })
  );
  return applyOccurrenceFiltersAndSort(rows, filterState).slice(0, MAX_EXPORT_ROWS);
}
