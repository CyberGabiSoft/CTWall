package handlers

import "testing"

func TestParseAlertingConnectorType_MVPDisabledTypesRejected(t *testing.T) {
	if _, err := parseAlertingConnectorType("pagerduty"); err == nil {
		t.Fatalf("expected pagerduty to be rejected in MVP")
	}
	if _, err := parseAlertingConnectorType("telegram"); err == nil {
		t.Fatalf("expected telegram to be rejected in MVP")
	}
	if _, err := parseAlertingConnectorType("smtp"); err != nil {
		t.Fatalf("expected smtp to remain enabled in MVP, got error: %v", err)
	}
}
