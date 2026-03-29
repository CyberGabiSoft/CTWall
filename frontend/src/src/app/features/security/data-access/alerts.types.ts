export type AlertSeverity = 'INFO' | 'WARN' | 'ERROR';
export type AlertGroupStatus = 'OPEN' | 'ACKNOWLEDGED' | 'CLOSED';

export interface AlertGroup {
  id: string;
  projectId: string;
  severity: AlertSeverity;
  category: string;
  type: string;
  status: AlertGroupStatus;
  groupKey: string;
  title: string;
  entityRef?: string | null;
  occurrences: number;
  firstSeenAt: string;
  lastSeenAt: string;
  lastNotifiedAt?: string | null;
  acknowledgedAt?: string | null;
  acknowledgedBy?: string | null;
  closedAt?: string | null;
  closedBy?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AlertOccurrence {
  id: string;
  projectId: string;
  groupId: string;
  severity: AlertSeverity;
  category: string;
  type: string;
  title: string;
  occurredAt: string;
  productId?: string | null;
  scopeId?: string | null;
  testId?: string | null;
  entityRef?: string | null;
  details: unknown;
  createdAt: string;
}

export interface AlertGroupsListResponse {
  items: AlertGroup[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface AlertOccurrencesListResponse {
  items: AlertOccurrence[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export type AlertRouteTargetType = 'PRODUCT' | 'SCOPE' | 'TEST';

export interface AlertRouteRef {
  targetType: AlertRouteTargetType;
  targetId: string;
}

export type AlertingConnectorType =
  | 'discord'
  | 'smtp'
  | 'msteamsv2'
  | 'jira'
  | 'alertmanager_external'
  | 'opsgenie'
  | 'pagerduty'
  | 'pushover'
  | 'rocketchat'
  | 'slack'
  | 'sns'
  | 'telegram'
  | 'victorops'
  | 'webex'
  | 'webhook'
  | 'wechat';

export type ConnectorTestStatus = 'NOT_CONFIGURED' | 'PASSED' | 'FAILED';

export interface AlertingConnectorConnectionStatus {
  configured: boolean;
  connectionEnabled: boolean;
  lastTestStatus: ConnectorTestStatus;
  lastTestAt?: string | null;
  lastTestMessage?: string | null;
}

export interface AlertingConnectorState {
  type: AlertingConnectorType;
  projectId: string;
  alertingEnabled: boolean;
  jiraDedupRuleId?: string | null;
  routes: AlertRouteRef[];
  connectionStatus: AlertingConnectorConnectionStatus;
}

export interface AlertingConnectorUpsertRequest {
  enabled: boolean;
  jiraDedupRuleId?: string | null;
  routes: {
    productIds?: string[];
    scopeIds?: string[];
    testIds?: string[];
  };
}

export type AlertDedupScope = 'GLOBAL' | 'PRODUCT' | 'SCOPE' | 'TEST';
export type AlertMinSeverity = 'INFO' | 'WARNING' | 'ERROR';

export interface AlertDedupRule {
  id: string;
  projectId: string;
  alertType: string;
  dedupScope: AlertDedupScope;
  minSeverity?: AlertMinSeverity | null;
  productId?: string | null;
  scopeId?: string | null;
  testId?: string | null;
  enabled: boolean;
  createdAt?: string | null;
  updatedAt?: string | null;
}

export interface AlertDedupRulesResponse {
  items: AlertDedupRule[];
}

export interface PutAlertDedupRulesRequest {
  rules: Array<{
    dedupScope: AlertDedupScope;
    minSeverity?: AlertMinSeverity | null;
    productId?: string | null;
    scopeId?: string | null;
    testId?: string | null;
    enabled?: boolean;
  }>;
}
