export interface ScannerSummary {
  id: string;
  name: string;
  scannerType: string;
  version?: string;
  resultsPath?: string;
}

export interface MalwareSource {
  id: string;
  name: string;
  sourceType: string;
  baseUrl: string;
  configJson: Record<string, unknown>;
  isActive: boolean;
  createdAt: string;
  scanner?: ScannerSummary;
}

export interface MalwareSourceUpdatePayload {
  isActive?: boolean;
  baseUrl?: string;
  config?: Record<string, string>;
}

export interface SyncStartResponse {
  syncId: string;
  mode: 'full' | 'latest';
  status: string;
  startedAt: string;
}

export interface ScanComponentResult {
  id: string;
  componentPurl: string;
  componentHash?: string;
  analysisResultId?: string;
  scanId: string;
  sourceId: string;
  resultFilename?: string;
  evidence?: string;
  detailsJson: Record<string, unknown>;
  publishedAt?: string;
  modifiedAt?: string;
  detectVersion?: string;
  fixedVersion?: string;
  isMalware: boolean;
  createdAt: string;
}

export interface SyncHistoryEntry {
  id: string;
  actorId?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  createdAt: string;
}

// Recompute history entries share the same shape as sync history (backend AuditLog).
export type RecomputeHistoryEntry = SyncHistoryEntry;

export interface MalwareSummaryRecomputeResponse {
  enqueued: number;
}

export interface MalwareSourceResultsRecomputeResponse {
  status: string;
}

export type SecurityPostureRange = '24h' | '7d' | '30d' | '90d';
export type SecurityPostureBucket = 'day' | 'week';

export interface SecurityPostureScore {
  value: number;
  label: string;
}

export interface SecurityPostureKpis {
  totalProducts: number;
  malwareProducts: number;
  unknownPending: number;
  activeComponents: number;
  ingestFailures: number;
  ingestCompleted: number;
  ingestFailurePercent: number;
  osvSyncStatus: string;
  osvLastSyncAt?: string | null;
  osvErrors: number;
  openErrorEvents: number;
  queueBacklog: number;
  inventoryTopType: string;
  lastAnalysisAt?: string | null;
}

export interface SecurityPostureTopItem {
  name: string;
  value: number;
}

export interface SecurityPostureIngestBucket {
  bucketStart: string;
  imports: number;
  failures: number;
}

export interface SecurityPostureSyncBucket {
  bucketStart: string;
  runs: number;
  failures: number;
}

export interface SecurityPosturePackageType {
  packageType: string;
  count: number;
  percentage: number;
}

export interface SecurityPostureFailure {
  timestamp: string;
  component: string;
  summary: string;
  status: string;
}

export interface SecurityPostureUpload {
  id: string;
  timestamp: string;
  status: string;
  stage: string;
  componentsImported: number;
  productId?: string | null;
  scopeId?: string | null;
  testId?: string | null;
  productName: string;
  scopeName: string;
  testName: string;
  errorMessage?: string;
}

export interface SecurityPostureOverviewData {
  generatedAt: string;
  rangeStart: string;
  rangeEnd: string;
  projectId: string;
  topN: number;
  bucket: SecurityPostureBucket;
  score: SecurityPostureScore;
  kpis: SecurityPostureKpis;
  ingestTrend: SecurityPostureIngestBucket[];
  ingestFailureTop: SecurityPostureTopItem[];
  osvSyncTrend: SecurityPostureSyncBucket[];
  osvTopErrorStages: SecurityPostureTopItem[];
  inventoryTopTypesTotal: number;
  inventoryTopTypes: SecurityPosturePackageType[];
  recentUploads: SecurityPostureUpload[];
  recentFailures: SecurityPostureFailure[];
}

export interface SecurityPostureOverviewResponse {
  scope: 'project';
  projectId: string;
  range: SecurityPostureRange;
  bucket: SecurityPostureBucket;
  data: SecurityPostureOverviewData;
}
