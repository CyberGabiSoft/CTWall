export interface IngestProduct {
  id: string;
  name: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface IngestScope {
  id: string;
  name: string;
  productId?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface IngestTest {
  id: string;
  name: string;
  scopeId?: string | null;
  sbomStandard?: string | null;
  sbomSpecVersion?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface IngestResponse {
  productId: string;
  scopeId: string;
  testId: string;
  revisionId: string;
  sbomSha256?: string | null;
  componentsImportedCount?: number | null;
  createdAt?: string | null;
}
