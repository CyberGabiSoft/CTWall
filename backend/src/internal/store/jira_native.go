package store

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

type JiraConfigLevel string

const (
	JiraConfigLevelProduct JiraConfigLevel = "PRODUCT"
	JiraConfigLevelScope   JiraConfigLevel = "SCOPE"
	JiraConfigLevelTest    JiraConfigLevel = "TEST"
)

const (
	JiraDeliveryRetryAttemptsDefault       = 0
	JiraDeliveryRetryAttemptsMin           = 0
	JiraDeliveryRetryAttemptsMax           = 20
	JiraDeliveryRetryBackoffSecondsDefault = 10
	JiraDeliveryRetryBackoffSecondsMin     = 1
	JiraDeliveryRetryBackoffSecondsMax     = 3600
)

func normalizeJiraConfigLevel(raw string) JiraConfigLevel {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(JiraConfigLevelProduct):
		return JiraConfigLevelProduct
	case string(JiraConfigLevelScope):
		return JiraConfigLevelScope
	case string(JiraConfigLevelTest):
		return JiraConfigLevelTest
	default:
		return ""
	}
}

type JiraEntitySettings struct {
	ID                          uuid.UUID         `json:"id"`
	ProjectID                   uuid.UUID         `json:"projectId"`
	ConfigLevel                 JiraConfigLevel   `json:"configLevel"`
	ConfigTargetID              uuid.UUID         `json:"configTargetId"`
	IsEnabled                   bool              `json:"isEnabled"`
	JiraProjectKey              string            `json:"jiraProjectKey"`
	IssueType                   string            `json:"issueType"`
	DeliveryRetryAttempts       int               `json:"deliveryRetryAttempts"`
	DeliveryRetryBackoffSeconds int               `json:"deliveryRetryBackoffSeconds"`
	OpenTransitionName          string            `json:"openTransitionName,omitempty"`
	ResolveTransitionName       string            `json:"resolveTransitionName,omitempty"`
	IssueFields                 map[string]any    `json:"issueFields"`
	Labels                      []string          `json:"labels"`
	Components                  []string          `json:"components"`
	SeverityToPriorityMapping   map[string]string `json:"severityToPriorityMapping"`
	TicketSummaryTemplate       string            `json:"ticketSummaryTemplate"`
	CreatedAt                   time.Time         `json:"createdAt"`
	UpdatedAt                   time.Time         `json:"updatedAt"`
}

type JiraEntitySettingsUpsertInput struct {
	ProjectID                   uuid.UUID
	ConfigLevel                 JiraConfigLevel
	ConfigTargetID              uuid.UUID
	IsEnabled                   bool
	JiraProjectKey              string
	IssueType                   string
	DeliveryRetryAttempts       int
	DeliveryRetryBackoffSeconds int
	OpenTransitionName          string
	ResolveTransitionName       string
	IssueFields                 map[string]any
	Labels                      []string
	Components                  []string
	SeverityToPriorityMapping   map[string]string
	TicketSummaryTemplate       string
}

type JiraEffectiveSettings struct {
	ResolvedFromLevel JiraConfigLevel    `json:"resolvedFromLevel"`
	ResolvedTargetID  uuid.UUID          `json:"resolvedTargetId"`
	Settings          JiraEntitySettings `json:"settings"`
}

type JiraEffectiveSettingsResolveInput struct {
	ProjectID uuid.UUID
	ProductID *uuid.UUID
	ScopeID   *uuid.UUID
	TestID    *uuid.UUID
}

type JiraIssueMappingStatus string

const (
	JiraIssueMappingStatusOpen       JiraIssueMappingStatus = "OPEN"
	JiraIssueMappingStatusClosed     JiraIssueMappingStatus = "CLOSED"
	JiraIssueMappingStatusDead       JiraIssueMappingStatus = "DEAD"
	JiraIssueMappingStatusSuperseded JiraIssueMappingStatus = "SUPERSEDED"
)

func normalizeJiraIssueMappingStatus(raw string) JiraIssueMappingStatus {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(JiraIssueMappingStatusOpen):
		return JiraIssueMappingStatusOpen
	case string(JiraIssueMappingStatusClosed):
		return JiraIssueMappingStatusClosed
	case string(JiraIssueMappingStatusDead):
		return JiraIssueMappingStatusDead
	case string(JiraIssueMappingStatusSuperseded):
		return JiraIssueMappingStatusSuperseded
	default:
		return ""
	}
}

type JiraIssueMapping struct {
	ID                      uuid.UUID              `json:"id"`
	ProjectID               uuid.UUID              `json:"projectId"`
	ConfigLevel             JiraConfigLevel        `json:"configLevel"`
	ConfigTargetID          uuid.UUID              `json:"configTargetId"`
	AlertGroupID            uuid.UUID              `json:"alertGroupId"`
	DedupRuleID             *uuid.UUID             `json:"dedupRuleId,omitempty"`
	TestID                  *uuid.UUID             `json:"testId,omitempty"`
	ComponentPURL           string                 `json:"componentPurl,omitempty"`
	EffectiveConfigLevel    *JiraConfigLevel       `json:"effectiveConfigLevel,omitempty"`
	EffectiveConfigTargetID *uuid.UUID             `json:"effectiveConfigTargetId,omitempty"`
	JiraIssueKey            string                 `json:"jiraIssueKey,omitempty"`
	JiraIssueID             string                 `json:"jiraIssueId,omitempty"`
	Status                  JiraIssueMappingStatus `json:"status"`
	LastSyncedAt            *time.Time             `json:"lastSyncedAt,omitempty"`
	LastError               string                 `json:"lastError,omitempty"`
	ClosedAt                *time.Time             `json:"closedAt,omitempty"`
	CreatedAt               time.Time              `json:"createdAt"`
	UpdatedAt               time.Time              `json:"updatedAt"`
}

type JiraIssueMappingUpsertInput struct {
	ProjectID               uuid.UUID
	ConfigLevel             JiraConfigLevel
	ConfigTargetID          uuid.UUID
	AlertGroupID            uuid.UUID
	DedupRuleID             *uuid.UUID
	TestID                  *uuid.UUID
	ComponentPURL           string
	EffectiveConfigLevel    *JiraConfigLevel
	EffectiveConfigTargetID *uuid.UUID
	JiraIssueKey            string
	JiraIssueID             string
	Status                  JiraIssueMappingStatus
	LastSyncedAt            *time.Time
	LastError               string
	ClosedAt                *time.Time
}

type JiraIssueMappingsListFilter struct {
	Limit     int
	Offset    int
	Status    string
	Component string
	JiraKey   string
}

type JiraDeliveryAction string

const (
	JiraDeliveryActionCreate         JiraDeliveryAction = "CREATE"
	JiraDeliveryActionUpdate         JiraDeliveryAction = "UPDATE"
	JiraDeliveryActionReopen         JiraDeliveryAction = "REOPEN"
	JiraDeliveryActionResolve        JiraDeliveryAction = "RESOLVE"
	JiraDeliveryActionSupersedeClose JiraDeliveryAction = "SUPERSEDE_CLOSE"
	JiraDeliveryActionNoop           JiraDeliveryAction = "NOOP"
)

func normalizeJiraDeliveryAction(raw string) JiraDeliveryAction {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(JiraDeliveryActionCreate):
		return JiraDeliveryActionCreate
	case string(JiraDeliveryActionUpdate):
		return JiraDeliveryActionUpdate
	case string(JiraDeliveryActionReopen):
		return JiraDeliveryActionReopen
	case string(JiraDeliveryActionResolve):
		return JiraDeliveryActionResolve
	case string(JiraDeliveryActionSupersedeClose):
		return JiraDeliveryActionSupersedeClose
	case string(JiraDeliveryActionNoop):
		return JiraDeliveryActionNoop
	default:
		return ""
	}
}

type JiraDeliveryOutcome string

const (
	JiraDeliveryOutcomeSuccess JiraDeliveryOutcome = "SUCCESS"
	JiraDeliveryOutcomeRetry   JiraDeliveryOutcome = "RETRY"
	JiraDeliveryOutcomeDead    JiraDeliveryOutcome = "DEAD"
	JiraDeliveryOutcomeSkipped JiraDeliveryOutcome = "SKIPPED"
	JiraDeliveryOutcomeFailed  JiraDeliveryOutcome = "FAILED"
)

func normalizeJiraDeliveryOutcome(raw string) JiraDeliveryOutcome {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(JiraDeliveryOutcomeSuccess):
		return JiraDeliveryOutcomeSuccess
	case string(JiraDeliveryOutcomeRetry):
		return JiraDeliveryOutcomeRetry
	case string(JiraDeliveryOutcomeDead):
		return JiraDeliveryOutcomeDead
	case string(JiraDeliveryOutcomeSkipped):
		return JiraDeliveryOutcomeSkipped
	case string(JiraDeliveryOutcomeFailed):
		return JiraDeliveryOutcomeFailed
	default:
		return ""
	}
}

type JiraDeliveryAttemptInput struct {
	QueueJobID         *uuid.UUID
	ProjectID          uuid.UUID
	ConfigLevel        *JiraConfigLevel
	ConfigTargetID     *uuid.UUID
	AlertGroupID       *uuid.UUID
	DedupRuleID        *uuid.UUID
	JiraIssueMappingID *uuid.UUID
	AttemptNo          int
	Action             JiraDeliveryAction
	Outcome            JiraDeliveryOutcome
	HTTPStatus         *int
	ErrorCode          string
	ErrorMessage       string
}

type JiraDeliveryAttempt struct {
	ID                 uuid.UUID           `json:"id"`
	QueueJobID         *uuid.UUID          `json:"queueJobId,omitempty"`
	ProjectID          uuid.UUID           `json:"projectId"`
	ConfigLevel        *JiraConfigLevel    `json:"configLevel,omitempty"`
	ConfigTargetID     *uuid.UUID          `json:"configTargetId,omitempty"`
	AlertGroupID       *uuid.UUID          `json:"alertGroupId,omitempty"`
	DedupRuleID        *uuid.UUID          `json:"dedupRuleId,omitempty"`
	JiraIssueMappingID *uuid.UUID          `json:"jiraIssueMappingId,omitempty"`
	AttemptNo          int                 `json:"attemptNo"`
	Action             JiraDeliveryAction  `json:"action"`
	Outcome            JiraDeliveryOutcome `json:"outcome"`
	HTTPStatus         *int                `json:"httpStatus,omitempty"`
	ErrorCode          string              `json:"errorCode,omitempty"`
	ErrorMessage       string              `json:"errorMessage,omitempty"`
	CreatedAt          time.Time           `json:"createdAt"`
}

type JiraMetadataType string

const (
	JiraMetadataTypeProjects    JiraMetadataType = "PROJECTS"
	JiraMetadataTypeIssueTypes  JiraMetadataType = "ISSUE_TYPES"
	JiraMetadataTypeComponents  JiraMetadataType = "COMPONENTS"
	JiraMetadataTypePriorities  JiraMetadataType = "PRIORITIES"
	JiraMetadataTypeIssues      JiraMetadataType = "ISSUES"
	JiraMetadataTypeTransitions JiraMetadataType = "TRANSITIONS"
	JiraMetadataTypeIssueFields JiraMetadataType = "ISSUE_FIELDS"
)

func normalizeJiraMetadataType(raw string) JiraMetadataType {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(JiraMetadataTypeProjects):
		return JiraMetadataTypeProjects
	case string(JiraMetadataTypeIssueTypes):
		return JiraMetadataTypeIssueTypes
	case string(JiraMetadataTypeComponents):
		return JiraMetadataTypeComponents
	case string(JiraMetadataTypePriorities):
		return JiraMetadataTypePriorities
	case string(JiraMetadataTypeIssues):
		return JiraMetadataTypeIssues
	case string(JiraMetadataTypeTransitions):
		return JiraMetadataTypeTransitions
	case string(JiraMetadataTypeIssueFields):
		return JiraMetadataTypeIssueFields
	default:
		return ""
	}
}

type JiraMetadataCacheEntry struct {
	ID               uuid.UUID        `json:"id"`
	ProjectID        uuid.UUID        `json:"projectId"`
	BaseURLHash      string           `json:"baseUrlHash"`
	MetadataType     JiraMetadataType `json:"metadataType"`
	MetadataScopeKey string           `json:"metadataScopeKey"`
	PayloadJSON      []byte           `json:"payloadJson"`
	FetchedAt        time.Time        `json:"fetchedAt"`
	CreatedAt        time.Time        `json:"createdAt"`
	UpdatedAt        time.Time        `json:"updatedAt"`
}

type JiraMetadataCacheUpsertInput struct {
	ProjectID        uuid.UUID
	BaseURLHash      string
	MetadataType     JiraMetadataType
	MetadataScopeKey string
	PayloadJSON      []byte
	FetchedAt        *time.Time
}
