package audit

import (
	"encoding/json"
	"testing"

	"backend/internal/eventmeta"
)

func TestBuildDetails_DoesNotAllowOverridingRequiredKeys(t *testing.T) {
	raw, err := BuildDetails(DetailsBase{
		Category: eventmeta.CategoryAuthN,
		Severity: eventmeta.SeverityInfo,
		MinRole:  eventmeta.MinRoleWrite,
		EventKey: "authn.login_success",
	}, map[string]any{
		"category":   "system",
		"severity":   "ERROR",
		"min_role":   "admin",
		"event_key":  "system.overridden",
		"something":  "ok",
		"sync_id":    "123",
		"traceId":    "trace-1",
		"component":  "handler.test",
		"message":    "hello",
		"projectId":  "p1",
		"created_at": "2026-01-01",
	})
	if err != nil {
		t.Fatalf("BuildDetails error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := m["category"]; got != "authn" {
		t.Fatalf("category overridden: %v", got)
	}
	if got := m["severity"]; got != "INFO" {
		t.Fatalf("severity overridden: %v", got)
	}
	if got := m["min_role"]; got != "write" {
		t.Fatalf("min_role overridden: %v", got)
	}
	if got := m["event_key"]; got != "authn.login_success" {
		t.Fatalf("event_key overridden: %v", got)
	}
	if got := m["something"]; got != "ok" {
		t.Fatalf("extra field missing: %v", got)
	}
}

func TestBuildDetails_InvalidEventKeyRejected(t *testing.T) {
	if _, err := BuildDetails(DetailsBase{
		Category: eventmeta.CategoryAuthN,
		Severity: eventmeta.SeverityInfo,
		MinRole:  eventmeta.MinRoleWrite,
		EventKey: "AUTHN.BAD KEY",
	}, nil); err == nil {
		t.Fatalf("expected invalid event_key error")
	}
}

