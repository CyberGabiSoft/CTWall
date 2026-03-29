export type EventSeverity = 'INFO' | 'WARN' | 'ERROR';
export type EventStatus = 'open' | 'acknowledged';
export type EventMinRole = 'read' | 'write' | 'admin';

export interface EventAggregate {
  eventKey: string;
  category: string;
  severity: EventSeverity;
  minRole: EventMinRole;
  title: string;
  message: string;
  component: string;
  errorId?: string;
  projectId?: string;
  firstSeenAt: string;
  lastSeenAt: string;
  occurrences: number;
  acknowledgedAt?: string;
  status: EventStatus;
}

export interface EventsOpenCountResponse {
  count: number;
}

export interface EventsListResponse {
  items: EventAggregate[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

// Backend uses the same shape as existing audit log entries (e.g. sync history).
export interface AuditLogEntry {
  id: string;
  actorId?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  createdAt: string;
}

export interface EventDetailsResponse {
  event: EventAggregate;
  occurrences: AuditLogEntry[];
}

