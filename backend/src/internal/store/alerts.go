package store

import (
	"encoding/json"
	"strings"
	"time"

	"backend/internal/eventmeta"

	"github.com/google/uuid"
)

type AlertGroupStatus string

const (
	AlertGroupStatusOpen         AlertGroupStatus = "OPEN"
	AlertGroupStatusAcknowledged AlertGroupStatus = "ACKNOWLEDGED"
	AlertGroupStatusClosed       AlertGroupStatus = "CLOSED"
)

type AlertGroupsQuery struct {
	ProjectID   uuid.UUID
	Severities  []eventmeta.Severity
	Categories  []eventmeta.Category
	Types       []string
	Status      []AlertGroupStatus
	Query       string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
	OrderBySeen string // "last_seen" (default) or "first_seen"
}

type AlertOccurrencesQuery struct {
	ProjectID  uuid.UUID
	GroupID    *uuid.UUID
	Severities []eventmeta.Severity
	Categories []eventmeta.Category
	Types      []string
	Query      string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

type AlertGroupUpsert struct {
	ProjectID uuid.UUID
	Severity  eventmeta.Severity
	Category  eventmeta.Category
	Type      string
	GroupKey  string
	Title     string
	EntityRef *string
}

type AlertOccurrenceInsert struct {
	ProjectID  uuid.UUID
	GroupID    uuid.UUID
	OccurredAt *time.Time
	ProductID  *uuid.UUID
	ScopeID    *uuid.UUID
	TestID     *uuid.UUID
	EntityRef  *string
	Details    json.RawMessage
}

type AlertOccurrenceContext struct {
	ProductID *uuid.UUID `json:"productId,omitempty"`
	ScopeID   *uuid.UUID `json:"scopeId,omitempty"`
	TestID    *uuid.UUID `json:"testId,omitempty"`
}

type AlertGroupComponentContext struct {
	ProductID     uuid.UUID `json:"productId"`
	ScopeID       uuid.UUID `json:"scopeId"`
	TestID        uuid.UUID `json:"testId"`
	ComponentPURL string    `json:"componentPurl"`
	MalwarePURL   string    `json:"malwarePurl"`
}

type AlertConnectorSettings struct {
	ProjectID       uuid.UUID       `json:"projectId"`
	ConnectorType   ConnectorType   `json:"connectorType"`
	IsEnabled       bool            `json:"isEnabled"`
	JiraDedupRuleID *uuid.UUID      `json:"jiraDedupRuleId,omitempty"`
	UpdatedAt       time.Time       `json:"updatedAt"`
	Routes          []AlertRouteRef `json:"routes"`
}

type AlertRouteTargetType string

const (
	AlertRouteTargetProduct AlertRouteTargetType = "PRODUCT"
	AlertRouteTargetScope   AlertRouteTargetType = "SCOPE"
	AlertRouteTargetTest    AlertRouteTargetType = "TEST"
)

type AlertRouteRef struct {
	TargetType AlertRouteTargetType `json:"targetType"`
	TargetID   uuid.UUID            `json:"targetId"`
}

type AlertDedupScope string

const (
	AlertDedupScopeGlobal  AlertDedupScope = "GLOBAL"
	AlertDedupScopeProduct AlertDedupScope = "PRODUCT"
	AlertDedupScopeScope   AlertDedupScope = "SCOPE"
	AlertDedupScopeTest    AlertDedupScope = "TEST"
)

func normalizeAlertDedupScope(raw string) AlertDedupScope {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(AlertDedupScopeGlobal):
		return AlertDedupScopeGlobal
	case string(AlertDedupScopeProduct):
		return AlertDedupScopeProduct
	case string(AlertDedupScopeScope):
		return AlertDedupScopeScope
	case string(AlertDedupScopeTest):
		return AlertDedupScopeTest
	default:
		return AlertDedupScope("")
	}
}

type AlertMinSeverity string

const (
	AlertMinSeverityInfo    AlertMinSeverity = "INFO"
	AlertMinSeverityWarning AlertMinSeverity = "WARNING"
	AlertMinSeverityError   AlertMinSeverity = "ERROR"
)

func normalizeAlertMinSeverity(raw string) AlertMinSeverity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(AlertMinSeverityInfo):
		return AlertMinSeverityInfo
	case "WARN", string(AlertMinSeverityWarning):
		return AlertMinSeverityWarning
	case string(AlertMinSeverityError):
		return AlertMinSeverityError
	default:
		return AlertMinSeverity("")
	}
}

type AlertDedupRuleInput struct {
	AlertType   string
	DedupScope  AlertDedupScope
	ProductID   *uuid.UUID
	ScopeID     *uuid.UUID
	TestID      *uuid.UUID
	MinSeverity AlertMinSeverity
	Enabled     bool
}

type AlertDedupRuleResolutionInput struct {
	ProjectID uuid.UUID
	AlertType string
	ProductID *uuid.UUID
	ScopeID   *uuid.UUID
	TestID    *uuid.UUID
}

type AlertDetectionMode string

const (
	AlertDetectionModePURLVersionSmart   AlertDetectionMode = "PURL_VERSION_SMART"
	AlertDetectionModePURLContainsPrefix AlertDetectionMode = "PURL_CONTAINS_PREFIX"
)

func normalizeAlertDetectionMode(raw string) AlertDetectionMode {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(AlertDetectionModePURLVersionSmart):
		return AlertDetectionModePURLVersionSmart
	case string(AlertDetectionModePURLContainsPrefix):
		return AlertDetectionModePURLContainsPrefix
	default:
		return AlertDetectionMode("")
	}
}

func isValidAlertDetectionMode(raw string) bool {
	return normalizeAlertDetectionMode(raw) != AlertDetectionMode("")
}

func alertDetectionModeKey(mode AlertDetectionMode) string {
	switch normalizeAlertDetectionMode(string(mode)) {
	case AlertDetectionModePURLVersionSmart:
		return "purl_version_smart"
	case AlertDetectionModePURLContainsPrefix:
		return "purl_contains_prefix"
	default:
		return ""
	}
}

type AlertDetectionModeInput struct {
	Mode     AlertDetectionMode
	Enabled  bool
	Severity eventmeta.Severity
	// LookbackDays applies only to PURL_CONTAINS_PREFIX:
	// nil => all history; >0 => last N days.
	LookbackDays *int
}

func normalizeAlertDetectionSeverity(raw string) eventmeta.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case string(eventmeta.SeverityInfo):
		return eventmeta.SeverityInfo
	case string(eventmeta.SeverityWarn), "WARNING":
		return eventmeta.SeverityWarn
	case string(eventmeta.SeverityError):
		return eventmeta.SeverityError
	default:
		return eventmeta.Severity("")
	}
}

func defaultAlertDetectionModeInputs() []AlertDetectionModeInput {
	return []AlertDetectionModeInput{
		{
			Mode:         AlertDetectionModePURLVersionSmart,
			Enabled:      true,
			Severity:     eventmeta.SeverityError,
			LookbackDays: nil,
		},
		{
			Mode:         AlertDetectionModePURLContainsPrefix,
			Enabled:      false,
			Severity:     eventmeta.SeverityWarn,
			LookbackDays: nil,
		},
	}
}
