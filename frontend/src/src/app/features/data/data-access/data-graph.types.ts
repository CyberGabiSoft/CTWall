export type DataGraphScope = 'project';
export type DataGraphProducer = 'syft' | 'trivy' | 'grype' | 'other';

export interface DataGraphNode {
  id: string;
  label: string;
  purl: string;
  pkgType: string;
  pkgNamespace?: string;
  version?: string;
  isMalware: boolean;
  malwareCount: number;
}

export interface DataGraphEdge {
  from: string;
  to: string;
  relationshipType: string;
}

export interface DataGraphChainMetadata {
  projectId: string;
  productId: string;
  productName: string;
  scopeId: string;
  scopeName: string;
  testId: string;
  testName: string;
  revisionId: string;
  sbomStandard: string;
  sbomSpecVersion: string;
  sbomProducer: string;
  generatedAt: string;
  truncated: boolean;
  truncationReason?: string;
  nodeCount: number;
  edgeCount: number;
}

export interface DataGraphChainData {
  nodes: DataGraphNode[];
  edges: DataGraphEdge[];
  metadata: DataGraphChainMetadata;
}

export interface DataGraphChainResponse {
  scope: DataGraphScope;
  projectId: string;
  data: DataGraphChainData;
}

export interface DataGraphComponentIdentity {
  id: string;
  revisionId: string;
  purl: string;
  pkgName: string;
  version: string;
  pkgType: string;
  pkgNamespace?: string;
  sbomType?: string;
  publisher?: string;
  supplier?: string;
  licenses?: unknown;
  properties?: unknown;
  createdAt?: string;
  projectId: string;
  projectName: string;
  productId: string;
  productName: string;
  scopeId: string;
  scopeName: string;
  testId: string;
  testName: string;
  sbomStandard: string;
  sbomSpecVersion: string;
  sbomProducer: string;
  revisionIsActive: boolean;
  revisionCreatedAt?: string;
}

export interface DataGraphMalwareSummary {
  verdict: 'MALWARE' | 'CLEAN' | 'UNKNOWN' | string;
  findingsCount: number;
  summary?: string;
  scannedAt?: string | null;
  validUntil?: string | null;
}

export interface DataGraphComponentFinding {
  id: string;
  componentPurl: string;
  malwarePurl: string;
  sourceMalwareInputResultId: string;
  matchType: string;
  createdAt?: string;
  updatedAt?: string;
  triageStatus: string;
  triagePriority?: string | null;
  effectivePriority: string;
  triageReason?: string | null;
  triageExpiresAt?: string | null;
  triageUpdatedAt?: string | null;
}

export interface DataGraphRawFinding {
  id: string;
  componentPurl: string;
  componentHash?: string | null;
  analysisResultId?: string | null;
  scanId: string;
  sourceId: string;
  resultFilename?: string | null;
  evidence?: string | null;
  detailsJson?: Record<string, unknown> | null;
  publishedAt?: string | null;
  modifiedAt?: string | null;
  detectVersion?: string | null;
  fixedVersion?: string | null;
  isMalware: boolean;
  createdAt?: string;
}

export interface DataGraphQueueHistoryItem {
  id: string;
  componentPurl: string;
  status: string;
  reason: string;
  attempts?: number;
  lastError?: string | null;
  lockedAt?: string | null;
  lockedBy?: string | null;
  scheduledFor?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  completedAt?: string | null;
}

export interface DataGraphOccurrence {
  productId: string;
  productName: string;
  scopeId: string;
  scopeName: string;
  testId: string;
  testName: string;
  revisionId: string;
  revisionIsActive: boolean;
  revisionCreatedAt?: string;
  sbomProducer: string;
}

export interface DataGraphComponentDetailsData {
  identity: DataGraphComponentIdentity;
  malwareSummary: DataGraphMalwareSummary;
  malwareFindings: DataGraphComponentFinding[];
  rawFindings: DataGraphRawFinding[];
  queueHistory: DataGraphQueueHistoryItem[];
  occurrences: DataGraphOccurrence[];
}

export interface DataGraphComponentDetailsResponse {
  scope: DataGraphScope;
  projectId: string;
  testId: string;
  revisionId: string;
  purl: string;
  data: DataGraphComponentDetailsData;
}

