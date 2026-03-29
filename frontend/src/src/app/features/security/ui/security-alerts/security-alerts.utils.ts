import { AdvancedFilterMode } from '../../../../shared/ui/advanced-filter-panel/advanced-filter-panel.component';
import {
  AlertDedupRule,
  AlertDedupScope,
  AlertMinSeverity,
  AlertingConnectorState
} from '../../data-access/alerts.types';

export function matchesAdvancedFilter(
  value: string,
  mode: AdvancedFilterMode,
  query: string,
  selected: string[]
): boolean {
  const text = (value ?? '').toString();
  if (mode === 'contains') {
    const q = (query ?? '').trim().toLowerCase();
    if (!q) {
      return true;
    }
    return text.toLowerCase().includes(q);
  }
  if (!selected || selected.length === 0) {
    return true;
  }
  return selected.some((v) => (v ?? '').toString() === text);
}

export function sortedOptions(values: string[]): string[] {
  const uniq = Array.from(
    new Set(values.map((v) => (v ?? '').toString()).filter((v) => v && v !== '-'))
  );
  return uniq.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
}

export function formatDate(value: string | null | undefined): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

export function groupDedupeKeys(groupKey: string | null | undefined): string {
  const raw = (groupKey ?? '').trim();
  if (!raw) {
    return '-';
  }
  const keys = raw
    .split('|')
    .map((part) => {
      const index = part.indexOf(':');
      if (index <= 0) {
        return '';
      }
      return part.slice(0, index).trim();
    })
    .filter((value) => !!value);
  if (keys.length === 0) {
    return raw;
  }
  return Array.from(new Set(keys)).join(' | ');
}

export function groupDedupRule(groupKey: string | null | undefined): string {
  const scopeRaw = groupKeyPart(groupKey, 'dedup_on').toLowerCase();
  if (scopeRaw === 'test') {
    const target = groupKeyPart(groupKey, 'test_id');
    return target ? `TEST (${target})` : 'TEST';
  }
  if (scopeRaw === 'scope') {
    const target = groupKeyPart(groupKey, 'scope_id');
    return target ? `SCOPE (${target})` : 'SCOPE';
  }
  if (scopeRaw === 'product') {
    const target = groupKeyPart(groupKey, 'product_id');
    return target ? `PRODUCT (${target})` : 'PRODUCT';
  }
  if (scopeRaw) {
    return scopeRaw.toUpperCase();
  }
  return 'GLOBAL';
}

export function isKnownKey<T extends string>(value: string, keys: readonly T[]): value is T {
  return keys.includes(value as T);
}

export function detailsStringValue(details: unknown, key: string): string {
  if (!details || typeof details !== 'object') {
    return '';
  }
  const rec = details as Record<string, unknown>;
  // eslint-disable-next-line security/detect-object-injection
  return typeof rec[key] === 'string' ? (rec[key] as string) : '';
}

export function normalizeOptionalID(value: string | null | undefined): string {
  return (value ?? '').trim();
}

export function normalizeMinSeverity(value: string | null | undefined): AlertMinSeverity {
  const normalized = (value ?? '').trim().toUpperCase();
  if (normalized === 'ERROR') {
    return 'ERROR';
  }
  if (normalized === 'WARNING') {
    return 'WARNING';
  }
  return 'INFO';
}

interface DedupTargetOption {
  id: string;
  name: string;
}

export function dedupTargetSummary(
  rule: AlertDedupRule,
  products: readonly DedupTargetOption[],
  scopes: readonly DedupTargetOption[],
  tests: readonly DedupTargetOption[]
): string {
  const scope = (rule.dedupScope ?? 'GLOBAL') as AlertDedupScope;
  if (scope === 'GLOBAL') {
    return 'All products/scopes/tests in project';
  }
  if (scope === 'PRODUCT') {
    const id = normalizeOptionalID(rule.productId);
    if (!id) {
      return '-';
    }
    const product = products.find((item) => item.id === id);
    return product ? `Product: ${product.name}` : `Product: ${id}`;
  }
  if (scope === 'SCOPE') {
    const id = normalizeOptionalID(rule.scopeId);
    if (!id) {
      return '-';
    }
    const scopeItem = scopes.find((item) => item.id === id);
    return scopeItem ? `Scope: ${scopeItem.name}` : `Scope: ${id}`;
  }
  const id = normalizeOptionalID(rule.testId);
  if (!id) {
    return '-';
  }
  const test = tests.find((item) => item.id === id);
  return test ? `Test: ${test.name}` : `Test: ${id}`;
}

export function dedupRuleOptionLabel(
  rule: AlertDedupRule,
  products: readonly DedupTargetOption[],
  scopes: readonly DedupTargetOption[],
  tests: readonly DedupTargetOption[]
): string {
  const severity = normalizeMinSeverity(rule.minSeverity ?? 'INFO');
  return `${rule.dedupScope} • ${dedupTargetSummary(rule, products, scopes, tests)} • min ${severity}`;
}

export function dedupRuleIdentity(rule: AlertDedupRule): string {
  return [
    (rule.alertType ?? '').trim().toLowerCase(),
    (rule.dedupScope ?? '').trim().toUpperCase(),
    normalizeOptionalID(rule.productId ?? ''),
    normalizeOptionalID(rule.scopeId ?? ''),
    normalizeOptionalID(rule.testId ?? '')
  ].join('|');
}

export function normalizeDedupRules(items: AlertDedupRule[]): AlertDedupRule[] {
  const rank = (scope: AlertDedupScope): number => {
    if (scope === 'TEST') return 1;
    if (scope === 'SCOPE') return 2;
    if (scope === 'PRODUCT') return 3;
    return 4;
  };
  const cleaned = (items ?? []).map((rule) => ({
    ...rule,
    alertType: (rule.alertType ?? 'malware.detected').trim() || 'malware.detected',
    dedupScope: ((rule.dedupScope ?? 'GLOBAL').trim().toUpperCase() as AlertDedupScope),
    minSeverity: normalizeMinSeverity(rule.minSeverity ?? 'INFO'),
    productId: normalizeOptionalID(rule.productId) || null,
    scopeId: normalizeOptionalID(rule.scopeId) || null,
    testId: normalizeOptionalID(rule.testId) || null
  }));
  return [...cleaned].sort((left, right) => {
    const byScope = rank(left.dedupScope) - rank(right.dedupScope);
    if (byScope !== 0) {
      return byScope;
    }
    return dedupRuleIdentity(left).localeCompare(dedupRuleIdentity(right), undefined, {
      sensitivity: 'base'
    });
  });
}

export function serializeDedupRules(items: AlertDedupRule[]): string {
  return JSON.stringify(
    normalizeDedupRules(items).map((rule) => ({
      alertType: rule.alertType,
      dedupScope: rule.dedupScope,
      minSeverity: normalizeMinSeverity(rule.minSeverity ?? 'INFO'),
      productId: normalizeOptionalID(rule.productId),
      scopeId: normalizeOptionalID(rule.scopeId),
      testId: normalizeOptionalID(rule.testId),
      enabled: !!rule.enabled
    }))
  );
}

export function connectorRouteIds(
  connector: AlertingConnectorState,
  targetType: 'PRODUCT' | 'SCOPE' | 'TEST'
): string[] {
  const routes = connector.routes ?? [];
  const out: string[] = [];
  for (const route of routes) {
    if ((route.targetType ?? '').toUpperCase() !== targetType) {
      continue;
    }
    const id = normalizeOptionalID(route.targetId);
    if (!id || out.includes(id)) {
      continue;
    }
    out.push(id);
  }
  return out;
}

export function isNilUUID(value: string | null | undefined): boolean {
  const normalized = (value ?? '').trim().toLowerCase();
  return normalized === '' || normalized === '00000000-0000-0000-0000-000000000000';
}

export function groupKeyPart(groupKey: string | null | undefined, key: string): string {
  const raw = (groupKey ?? '').trim();
  if (!raw) {
    return '';
  }
  const prefix = `${key}:`;
  for (const part of raw.split('|')) {
    const segment = part.trim();
    if (!segment.startsWith(prefix)) {
      continue;
    }
    return segment.slice(prefix.length).trim();
  }
  return '';
}
