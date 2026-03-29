import { Router } from '@angular/router';
import { buildExtendedFilterContextQueryParams } from '../../../../shared/utils/extended-filter-routing';
import { AlertsApi } from '../../data-access/alerts.api';
import { AlertGroup, AlertOccurrence } from '../../data-access/alerts.types';
import { detailsStringValue, groupKeyPart } from './security-alerts.utils';

export const MALWARE_SUMMARY_TABLE_ID = 'malware_summary';

interface ExplorerNavigation {
  queryParams: Record<string, string | null>;
}

interface GroupExplorerContext {
  productId: string;
  scopeId: string;
  testId: string;
}

function readGroupExplorerContext(row: AlertGroup): GroupExplorerContext {
  return {
    productId: groupKeyPart(row.groupKey, 'product_id'),
    scopeId: groupKeyPart(row.groupKey, 'scope_id'),
    testId: groupKeyPart(row.groupKey, 'test_id'),
  };
}

export function buildGroupExplorerNavigation(
  row: AlertGroup,
  tableId = MALWARE_SUMMARY_TABLE_ID
): ExplorerNavigation {
  const malwarePurl = groupKeyPart(row.groupKey, 'malware_purl') || (row.entityRef ?? '').trim();
  const context = readGroupExplorerContext(row);
  const contextParams = buildExtendedFilterContextQueryParams(tableId, {
    productId: context.productId,
    scopeId: context.scopeId,
    testId: context.testId,
    malwarePurl,
  });
  return {
    queryParams: {
      ...contextParams,
      focusProductId: context.productId || null,
      focusScopeId: context.scopeId || null,
      focusTestId: context.testId || null,
      productId: context.productId || null,
      scopeId: context.scopeId || null,
      testId: context.testId || null,
      malwarePurl: malwarePurl || null,
    },
  };
}

export function buildOccurrenceExplorerNavigation(
  row: AlertOccurrence,
  tableId = MALWARE_SUMMARY_TABLE_ID
): ExplorerNavigation | null {
  const testId = (row.testId ?? '').trim();
  const scopeId = (row.scopeId ?? '').trim();
  const productId = (row.productId ?? '').trim();
  const componentPurl = detailsStringValue(row.details, 'componentPurl') || (row.entityRef ?? '');
  const malwarePurl = detailsStringValue(row.details, 'malwarePurl');
  if (!testId && !scopeId && !productId) {
    return null;
  }
  const contextParams = buildExtendedFilterContextQueryParams(tableId, {
    productId,
    scopeId,
    testId,
    componentPurl,
    malwarePurl,
  });
  return {
    queryParams: {
      ...contextParams,
      focusProductId: productId || null,
      focusScopeId: scopeId || null,
      focusTestId: testId || null,
      componentPurl: componentPurl || null,
      malwarePurl: malwarePurl || null,
    },
  };
}

export async function openGroupInExplorer(
  router: Router,
  row: AlertGroup,
  tableId = MALWARE_SUMMARY_TABLE_ID
): Promise<boolean> {
  const navigation = buildGroupExplorerNavigation(row, tableId);
  return router.navigate(['/security/explorer'], { queryParams: navigation.queryParams });
}

export async function openOccurrenceInExplorer(
  router: Router,
  row: AlertOccurrence,
  tableId = MALWARE_SUMMARY_TABLE_ID
): Promise<boolean> {
  const navigation = buildOccurrenceExplorerNavigation(row, tableId);
  if (!navigation) {
    return false;
  }
  return router.navigate(['/security/explorer'], { queryParams: navigation.queryParams });
}

export function acknowledgeAlertGroup(api: AlertsApi, groupId: string): Promise<void> {
  return api.acknowledgeGroup(groupId);
}

export function closeAlertGroup(api: AlertsApi, groupId: string): Promise<void> {
  return api.closeGroup(groupId);
}
