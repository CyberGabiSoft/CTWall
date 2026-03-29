package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"backend/internal/eventmeta"
)

// DetailsBase defines the minimal, required contract for audit_logs.details persisted in DB.
// Required keys are validated at write-time by backend/internal/eventmeta.
type DetailsBase struct {
	Category eventmeta.Category
	Severity eventmeta.Severity
	MinRole  eventmeta.MinRole

	// Optional fields used by Events UI aggregation and diagnostics.
	EventKey  string
	ProjectID string
	TraceID   string
	Title     string
	Message   string
	Component string
	ErrorID   string
}

// BuildDetails builds a JSON payload for audit_logs.details.
// It enforces required keys and prevents overriding the required contract keys via extra.
func BuildDetails(base DetailsBase, extra map[string]any) (json.RawMessage, error) {
	category := strings.TrimSpace(string(base.Category))
	severity := strings.TrimSpace(string(base.Severity))
	minRole := strings.TrimSpace(string(base.MinRole))
	eventKey := strings.TrimSpace(base.EventKey)
	if category == "" || severity == "" || minRole == "" || eventKey == "" {
		return nil, fmt.Errorf("details base fields required")
	}
	if !eventmeta.ValidEventKey(eventKey) {
		return nil, fmt.Errorf("invalid event_key")
	}
	m := map[string]any{
		"category":  category,
		"severity":  severity,
		"min_role":  minRole,
		"event_key": eventKey,
	}
	if strings.TrimSpace(base.ProjectID) != "" {
		m["projectId"] = strings.TrimSpace(base.ProjectID)
	}
	if strings.TrimSpace(base.TraceID) != "" {
		m["traceId"] = strings.TrimSpace(base.TraceID)
	}
	if strings.TrimSpace(base.Title) != "" {
		m["title"] = strings.TrimSpace(base.Title)
	}
	if strings.TrimSpace(base.Message) != "" {
		m["message"] = strings.TrimSpace(base.Message)
	}
	if strings.TrimSpace(base.Component) != "" {
		m["component"] = strings.TrimSpace(base.Component)
	}
	if strings.TrimSpace(base.ErrorID) != "" {
		m["errorId"] = strings.TrimSpace(base.ErrorID)
	}

	for k, v := range extra {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		// Do not allow overriding required keys.
		switch key {
		case "category", "severity", "min_role", "event_key":
			continue
		}
		// Sanitize common string payloads to reduce log/DB injection risk and control characters.
		if s, ok := v.(string); ok {
			m[key] = SanitizeLogValue(s)
			continue
		}
		m[key] = v
	}

	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return raw, nil
}
