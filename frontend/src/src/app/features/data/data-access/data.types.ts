export interface ProductSummary {
  id: string;
  name: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface ScopeSummary {
  id: string;
  name: string;
  productId?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface SbomTypeSummary {
  standard: string;
  specVersion: string;
}

export interface TestSummary {
  id: string;
  name: string;
  scopeId?: string | null;
  sbomType?: SbomTypeSummary | null;
  isPublic?: boolean | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
}

export interface TestRevisionSummary {
  id: string;
  testId?: string | null;
  sbomSha256?: string | null;
  sbomProducer?: string | null;
  tags?: string[] | null;
  metadataJson?: unknown | null;
  sbomMetadataJson?: unknown | null;
  componentsImportedCount?: number | null;
  isActive?: boolean | null;
  lastModifiedAt?: string | null;
  createdAt?: string | null;
}

export interface TestRevisionChangeSummary {
  toRevisionId: string;
  projectId: string;
  testId: string;
  fromRevisionId?: string | null;
  addedCount: number;
  removedCount: number;
  unchangedCount: number;
  reappearedCount: number;
  status: string;
  computedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
}

export interface TestRevisionFindingDiff {
  id: string;
  projectId: string;
  testId: string;
  fromRevisionId?: string | null;
  toRevisionId: string;
  findingType: string;
  diffType: string;
  componentPurl: string;
  malwarePurl: string;
  createdAt?: string | null;
}

export interface ComponentSummary {
  id: string;
  revisionId?: string | null;
  purl?: string | null;
  pkgName?: string | null;
  version?: string | null;
  pkgType?: string | null;
  pkgNamespace?: string | null;
  sbomType?: string | null;
  publisher?: string | null;
  supplier?: string | null;
  licenses?: unknown | null;
  properties?: unknown | null;
  createdAt?: string | null;
}

export type DataSection = 'products' | 'scopes' | 'tests';

export type JiraConfigLevel = 'PRODUCT' | 'SCOPE' | 'TEST';

export interface JiraEntitySettings {
  id: string;
  projectId: string;
  configLevel: JiraConfigLevel;
  configTargetId: string;
  isEnabled: boolean;
  jiraProjectKey: string;
  issueType: string;
  deliveryRetryAttempts: number;
  deliveryRetryBackoffSeconds: number;
  openTransitionName?: string | null;
  resolveTransitionName?: string | null;
  issueFields?: Record<string, unknown> | null;
  labels: string[];
  components: string[];
  severityToPriorityMapping: Record<string, string>;
  ticketSummaryTemplate: string;
  createdAt?: string | null;
  updatedAt?: string | null;
}

export interface JiraEntitySettingsUpsertPayload {
  isEnabled: boolean;
  jiraProjectKey: string;
  issueType: string;
  deliveryRetryAttempts: number;
  deliveryRetryBackoffSeconds: number;
  openTransitionName?: string | null;
  resolveTransitionName?: string | null;
  issueFields?: Record<string, unknown> | null;
  labels: string[];
  components: string[];
  severityToPriorityMapping: Record<string, string>;
  ticketSummaryTemplate: string;
}

export interface JiraEffectiveSettings {
  resolvedFromLevel: JiraConfigLevel;
  resolvedTargetId: string;
  settings: JiraEntitySettings;
}

export interface JiraIssueMapping {
  id: string;
  projectId: string;
  configLevel: JiraConfigLevel;
  configTargetId: string;
  alertGroupId: string;
  dedupRuleId?: string | null;
  testId?: string | null;
  componentPurl?: string | null;
  effectiveConfigLevel?: JiraConfigLevel | null;
  effectiveConfigTargetId?: string | null;
  jiraIssueKey?: string | null;
  jiraIssueId?: string | null;
  status: 'OPEN' | 'CLOSED' | 'DEAD' | 'SUPERSEDED' | string;
  lastSyncedAt?: string | null;
  lastError?: string | null;
  closedAt?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
}

export interface JiraDeliveryAttempt {
  id: string;
  queueJobId?: string | null;
  projectId: string;
  configLevel?: JiraConfigLevel | null;
  configTargetId?: string | null;
  alertGroupId?: string | null;
  dedupRuleId?: string | null;
  jiraIssueMappingId?: string | null;
  attemptNo: number;
  action: 'CREATE' | 'UPDATE' | 'RESOLVE' | 'SUPERSEDE_CLOSE' | 'NOOP' | string;
  outcome: 'SUCCESS' | 'RETRY' | 'DEAD' | 'SKIPPED' | 'FAILED' | string;
  httpStatus?: number | null;
  errorCode?: string | null;
  errorMessage?: string | null;
  createdAt?: string | null;
}

export interface JiraIssueMappingsResponse {
  items: JiraIssueMapping[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface JiraDeliveriesResponse {
  items: JiraDeliveryAttempt[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface JiraManualRetryResponse {
  jobId: string;
  alertGroupId: string;
  eventState: 'FIRING' | 'RESOLVED' | string;
  queueState: 'PENDING' | 'RETRY' | 'IN_FLIGHT' | 'DONE' | 'DEAD' | string;
  attemptCount: number;
  nextAttemptAt: string;
}

export interface JiraMetadataProject {
  id: string;
  key: string;
  name: string;
}

export interface JiraMetadataIssueType {
  id: string;
  name: string;
}

export interface JiraMetadataComponent {
  id: string;
  name: string;
}

export interface JiraMetadataPriority {
  id: string;
  name: string;
}

export interface JiraMetadataIssue {
  id: string;
  key: string;
  summary: string;
  status: string;
}

export interface JiraMetadataTransition {
  id: string;
  name: string;
}

export interface JiraMetadataIssueFieldOption {
  id?: string;
  name?: string;
  value?: string;
}

export type JiraMetadataIssueFieldInputType = 'text' | 'number' | 'boolean' | 'single_select' | 'multi_select' | string;

export interface JiraMetadataIssueField {
  key: string;
  name: string;
  required: boolean;
  inputType: JiraMetadataIssueFieldInputType;
  allowedValues?: JiraMetadataIssueFieldOption[] | null;
}

export interface JiraMetadataResponse<T> {
  fromCache: boolean;
  baseUrl?: string;
  items: T[];
}
