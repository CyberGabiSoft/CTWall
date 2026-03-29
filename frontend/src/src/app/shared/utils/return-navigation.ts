import { ParamMap } from '@angular/router';

export const RETURN_TO_QUERY_PARAM = 'returnTo';

const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

export function sanitizeInternalReturnTo(raw: string | null | undefined): string | null {
  const value = (raw ?? '').trim();
  if (!value) {
    return null;
  }
  if (SCHEME_RE.test(value)) {
    return null;
  }
  if (!value.startsWith('/')) {
    return null;
  }
  if (value.startsWith('//')) {
    return null;
  }
  return value;
}

export function buildReturnToQueryParam(url: string): Record<string, string> {
  const sanitized = sanitizeInternalReturnTo(url);
  if (!sanitized) {
    return {};
  }
  return { [RETURN_TO_QUERY_PARAM]: sanitized };
}

export function readReturnToQueryParam(
  params: ParamMap,
  aliases: readonly string[] = [RETURN_TO_QUERY_PARAM]
): string | null {
  for (const alias of aliases) {
    const value = sanitizeInternalReturnTo(params.get(alias));
    if (value) {
      return value;
    }
  }
  return null;
}

