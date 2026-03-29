import { ParamMap } from '@angular/router';
import { defineOwnValue, getOwnValue } from './safe-object';

export type RoutingFilterMode = 'contains' | 'select';

export interface RoutingFilterValue {
  mode?: RoutingFilterMode;
  value?: string;
  values?: string[];
}

export type RoutingFilterMap<K extends string> = Partial<Record<K, RoutingFilterValue>>;
export type RoutingContextMap<K extends string> = Partial<Record<K, string>>;

export interface ParsedRoutingFilters<K extends string> {
  mode: Partial<Record<K, RoutingFilterMode>>;
  value: Partial<Record<K, string>>;
  values: Partial<Record<K, string[]>>;
  hasAny: boolean;
}

interface ParseOptions<K extends string> {
  tableId: string;
  keys: readonly K[];
  aliases?: Partial<Record<K, readonly string[]>>;
}

const VALID_MODES: readonly RoutingFilterMode[] = ['contains', 'select'];

function normalizeToken(raw: string): string {
  return raw.trim().replace(/[^a-zA-Z0-9_]/g, '_');
}

function toFilterModeParam(tableId: string, key: string): string {
  return `ef_${normalizeToken(tableId)}_${normalizeToken(key)}_mode`;
}

function toFilterValueParam(tableId: string, key: string): string {
  return `ef_${normalizeToken(tableId)}_${normalizeToken(key)}_value`;
}

function toFilterValuesParam(tableId: string, key: string): string {
  return `ef_${normalizeToken(tableId)}_${normalizeToken(key)}_values`;
}

function toContextParam(tableId: string, key: string): string {
  return `ef_${normalizeToken(tableId)}_ctx_${normalizeToken(key)}`;
}

function parseCsvValues(raw: string): string[] {
  return raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function pickFirstParam(params: ParamMap, names: readonly string[]): string {
  for (const name of names) {
    const value = (params.get(name) ?? '').trim();
    if (value) {
      return value;
    }
  }
  return '';
}

function parseMode(raw: string): RoutingFilterMode | null {
  const normalized = raw.trim().toLowerCase();
  return VALID_MODES.includes(normalized as RoutingFilterMode) ? (normalized as RoutingFilterMode) : null;
}

export function buildExtendedFilterQueryParams<K extends string>(
  tableId: string,
  filters: RoutingFilterMap<K>
): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const [rawKey, entry] of Object.entries(filters as Record<string, RoutingFilterValue | undefined>)) {
    if (!entry) {
      continue;
    }
    const modeKey = toFilterModeParam(tableId, rawKey);
    const valueKey = toFilterValueParam(tableId, rawKey);
    const valuesKey = toFilterValuesParam(tableId, rawKey);

    const mode = entry.mode ?? (entry.values && entry.values.length > 0 ? 'select' : 'contains');
    defineOwnValue(out, modeKey, mode);

    if (mode === 'select') {
      const values = (entry.values ?? []).map((item) => item.trim()).filter(Boolean);
      defineOwnValue(out, valuesKey, values.length > 0 ? values.join(',') : null);
      defineOwnValue(out, valueKey, null);
      continue;
    }

    const value = (entry.value ?? '').trim();
    defineOwnValue(out, valueKey, value || null);
    defineOwnValue(out, valuesKey, null);
  }
  return out;
}

export function buildExtendedFilterContextQueryParams<K extends string>(
  tableId: string,
  context: RoutingContextMap<K>
): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const [rawKey, rawValue] of Object.entries(context as Record<string, string | undefined>)) {
    const value = (rawValue ?? '').trim();
    defineOwnValue(out, toContextParam(tableId, rawKey), value || null);
  }
  return out;
}

export function readExtendedFilterQueryParams<K extends string>(
  params: ParamMap,
  options: ParseOptions<K>
): ParsedRoutingFilters<K> {
  const mode: Partial<Record<K, RoutingFilterMode>> = {};
  const value: Partial<Record<K, string>> = {};
  const values: Partial<Record<K, string[]>> = {};
  let hasAny = false;
  const modeOut = mode as Record<string, RoutingFilterMode>;
  const valueOut = value as Record<string, string>;
  const valuesOut = values as Record<string, string[]>;
  const aliasesMap = (options.aliases ?? {}) as Record<string, readonly string[]>;

  for (const key of options.keys) {
    const aliases = getOwnValue(aliasesMap, key) ?? [];
    const modeRaw = pickFirstParam(params, [toFilterModeParam(options.tableId, key)]);
    const parsedMode = parseMode(modeRaw);

    const valueRaw = pickFirstParam(params, [toFilterValueParam(options.tableId, key), ...aliases]);
    const valuesRaw = pickFirstParam(params, [toFilterValuesParam(options.tableId, key)]);
    const parsedValues = parseCsvValues(valuesRaw);

    if (parsedMode === 'select') {
      defineOwnValue(modeOut, key, 'select');
      if (parsedValues.length > 0) {
        defineOwnValue(valuesOut, key, parsedValues);
        hasAny = true;
      } else if (valueRaw) {
        defineOwnValue(valuesOut, key, [valueRaw]);
        hasAny = true;
      }
      continue;
    }

    if (parsedMode === 'contains') {
      defineOwnValue(modeOut, key, 'contains');
      if (valueRaw) {
        defineOwnValue(valueOut, key, valueRaw);
        hasAny = true;
      }
      continue;
    }

    // Fallback without explicit mode.
    if (parsedValues.length > 0) {
      defineOwnValue(modeOut, key, 'select');
      defineOwnValue(valuesOut, key, parsedValues);
      hasAny = true;
      continue;
    }
    if (valueRaw) {
      defineOwnValue(modeOut, key, 'contains');
      defineOwnValue(valueOut, key, valueRaw);
      hasAny = true;
    }
  }

  return { mode, value, values, hasAny };
}

export function readExtendedFilterContextQueryParams<K extends string>(
  params: ParamMap,
  options: ParseOptions<K>
): RoutingContextMap<K> {
  const out: RoutingContextMap<K> = {};
  const outRecord = out as Record<string, string>;
  const aliasesMap = (options.aliases ?? {}) as Record<string, readonly string[]>;
  for (const key of options.keys) {
    const aliases = getOwnValue(aliasesMap, key) ?? [];
    const value = pickFirstParam(params, [toContextParam(options.tableId, key), ...aliases]);
    if (value) {
      defineOwnValue(outRecord, key, value);
    }
  }
  return out;
}
