export type MalwareVerdict = 'MALWARE' | 'CLEAN' | 'UNKNOWN';

export interface ComponentOccurrence {
  componentId: string;
  revisionId: string;
  purl: string;
  pkgName: string;
  version: string;
  pkgType: string;
  pkgNamespace?: string;
  productId: string;
  productName: string;
  scopeId: string;
  scopeName: string;
  testId: string;
  testName: string;
  createdAt: string;
  malwareVerdict: MalwareVerdict;
  malwareFindingsCount: number;
  malwareScannedAt?: string | null;
  malwareValidUntil?: string | null;
}

export interface ComponentOccurrenceResponse {
  items: ComponentOccurrence[];
  total: number;
}

