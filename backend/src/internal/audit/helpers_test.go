package audit

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeLogValue(t *testing.T) {
	if SanitizeLogValue("   ") != "" {
		t.Fatalf("expected empty after trim")
	}
	long := strings.Repeat("a", maxLogValueRunes+10)
	if got := SanitizeLogValue(long); utf8.RuneCountInString(got) != maxLogValueRunes {
		t.Fatalf("expected truncation to %d runes", maxLogValueRunes)
	}
	if SanitizeLogValue("ok") != "ok" {
		t.Fatalf("expected unchanged value")
	}
}

func TestDecisionStatus(t *testing.T) {
	if DecisionStatus("AUTHN_ALLOW") != "allow" {
		t.Fatalf("expected allow status")
	}
	if DecisionStatus("AUTHZ_DENY") != "deny" {
		t.Fatalf("expected deny status")
	}
	if DecisionStatus("LOGIN_SUCCESS") != "allow" {
		t.Fatalf("expected allow status for success")
	}
	if DecisionStatus("LOGIN_FAILURE") != "deny" {
		t.Fatalf("expected deny status for failure")
	}
	if DecisionStatus("OTHER") != "" {
		t.Fatalf("expected empty status")
	}
}

func TestIPFromRequest(t *testing.T) {
	if IPFromRequest(nil) != "" {
		t.Fatalf("expected empty for nil request")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	if IPFromRequest(req) != "127.0.0.1" {
		t.Fatalf("expected host without port")
	}
	req.RemoteAddr = "127.0.0.1"
	if IPFromRequest(req) != "127.0.0.1" {
		t.Fatalf("expected raw address")
	}
	req.RemoteAddr = "bad"
	if IPFromRequest(req) != "" {
		t.Fatalf("expected empty for invalid address")
	}
}

func TestSanitizeIPAddress(t *testing.T) {
	if SanitizeIPAddress("bad") != "" {
		t.Fatalf("expected invalid ip to be empty")
	}
	if SanitizeIPAddress("127.0.0.1") != "127.0.0.1" {
		t.Fatalf("expected valid ip")
	}
	if SanitizeIPAddress("bad\x00") != "" {
		t.Fatalf("expected control chars to be rejected")
	}
}
