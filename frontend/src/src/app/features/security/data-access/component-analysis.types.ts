export type ComponentAnalysisStatus = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'FAILED';
export type ComponentAnalysisReason = 'SCHEDULED' | 'MANUAL' | 'BACKFILL';
export type ComponentAnalysisMatchType = 'EXACT' | 'CONTAINS_PREFIX';

export type MalwareFindingTriageStatus = 'OPEN' | 'RISK_ACCEPTED' | 'FALSE_POSITIVE' | 'FIXED';
export type MalwareFindingPriority = 'P1' | 'P2' | 'P3' | 'P4';

export interface ComponentAnalysisQueueItem {
  id: string;
  componentPurl: string;
  status: ComponentAnalysisStatus;
  reason: ComponentAnalysisReason;
  attempts?: number;
  lastError?: string | null;
  lockedAt?: string | null;
  lockedBy?: string | null;
  scheduledFor?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  completedAt?: string | null;
}

export interface ComponentAnalysisFinding {
  id: string;
  componentPurl: string;
  malwarePurl: string;
  sourceMalwareInputResultId?: string | null;
  matchType: ComponentAnalysisMatchType;
  createdAt?: string | null;
  updatedAt?: string | null;

  // Triage is contextual (per test); for endpoints without test context this may be defaulted by backend.
  triageStatus?: MalwareFindingTriageStatus;
  triagePriority?: MalwareFindingPriority | null;
  effectivePriority?: MalwareFindingPriority;
}

export interface MalwareResultSummary {
  id: string;
  componentPurl: string;
  componentHash?: string | null;
  verdict: 'MALWARE' | 'CLEAN' | 'UNKNOWN';
  findingsCount?: number | null;
  summary?: string | null;
  scannedAt?: string | null;
  validUntil?: string | null;
}

export interface MalwareRawFinding {
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
  createdAt?: string | null;
}

export interface TestRevisionMalwareSummary {
  revisionId: string;
  malwareComponentCount: number;
  computedAt?: string | null;
  updatedAt?: string | null;
  status: 'PENDING' | 'COMPUTED';
}
