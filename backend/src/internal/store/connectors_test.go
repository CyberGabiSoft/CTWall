package store

import "testing"

func TestAllConnectorTypesReturnsStableUniqueList(t *testing.T) {
	values := AllConnectorTypes()
	if len(values) == 0 {
		t.Fatalf("expected connector types")
	}

	seen := make(map[ConnectorType]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate connector type %q", value)
		}
		seen[value] = struct{}{}
	}

	if values[0] != ConnectorTypeDiscord {
		t.Fatalf("unexpected first connector type: %q", values[0])
	}
	if values[len(values)-1] != ConnectorTypeWeChat {
		t.Fatalf("unexpected last connector type: %q", values[len(values)-1])
	}
}

func TestAllMVPConnectorTypesContainsOnlyEnabledTypes(t *testing.T) {
	for _, value := range AllMVPConnectorTypes() {
		if !ValidConnectorType(value) {
			t.Fatalf("mvp list contains invalid connector type %q", value)
		}
		if !IsConnectorTypeEnabledInMVP(value) {
			t.Fatalf("mvp list contains disabled connector type %q", value)
		}
	}

	if IsConnectorTypeEnabledInMVP(ConnectorTypePushover) {
		t.Fatalf("expected pushover to be disabled in mvp")
	}
	if !IsConnectorTypeEnabledInMVP(ConnectorTypeJira) {
		t.Fatalf("expected jira to be enabled in mvp")
	}
}

func TestNormalizeConnectorType(t *testing.T) {
	testCases := []struct {
		name string
		raw  string
		want ConnectorType
	}{
		{name: "smtp", raw: "smtp", want: ConnectorTypeSMTP},
		{name: "email no longer alias", raw: " email ", want: ConnectorType("")},
		{name: "alertmanager alias", raw: "ALERTMANAGEREXTERNAL", want: ConnectorTypeAlertmanagerExternal},
		{name: "rocket chat alias", raw: "rocket_chat", want: ConnectorTypeRocketChat},
		{name: "unknown", raw: "xyz", want: ConnectorType("")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeConnectorType(tc.raw)
			if got != tc.want {
				t.Fatalf("NormalizeConnectorType(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestValidConnectorType(t *testing.T) {
	for _, value := range AllConnectorTypes() {
		if !ValidConnectorType(value) {
			t.Fatalf("expected valid connector type %q", value)
		}
	}
	if ValidConnectorType(ConnectorType("INVALID")) {
		t.Fatalf("expected invalid connector type to be rejected")
	}
}

func TestValidConnectorTestStatus(t *testing.T) {
	if !ValidConnectorTestStatus(ConnectorTestNotConfigured) {
		t.Fatalf("expected NOT_CONFIGURED to be valid")
	}
	if !ValidConnectorTestStatus(ConnectorTestPassed) {
		t.Fatalf("expected PASSED to be valid")
	}
	if !ValidConnectorTestStatus(ConnectorTestFailed) {
		t.Fatalf("expected FAILED to be valid")
	}
	if ValidConnectorTestStatus(ConnectorTestStatus("UNKNOWN")) {
		t.Fatalf("expected UNKNOWN to be invalid")
	}
}
