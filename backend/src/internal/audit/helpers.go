package audit

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxLogValueRunes = 256

// SanitizeLogValue removes control characters and trims long values for safe logs.
func SanitizeLogValue(value string) string {
	clean := sanitizePlainText(value)
	if clean == "" {
		return ""
	}
	if utf8.RuneCountInString(clean) <= maxLogValueRunes {
		return clean
	}
	runes := []rune(clean)
	return string(runes[:maxLogValueRunes])
}

// SanitizeIPAddress validates and cleans an IP string.
func SanitizeIPAddress(value string) string {
	clean := strings.TrimSpace(value)
	if clean == "" {
		return ""
	}
	if containsControl(clean) {
		return ""
	}
	if _, err := netip.ParseAddr(clean); err != nil {
		return ""
	}
	return clean
}

// IPFromRequest extracts the client IP from the request's RemoteAddr.
func IPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return SanitizeIPAddress(host)
	}
	return SanitizeIPAddress(raw)
}

// DecisionStatus maps audit action names into allow/deny.
func DecisionStatus(action string) string {
	switch {
	case strings.HasSuffix(action, "SUCCESS"), strings.HasSuffix(action, "_ALLOW"):
		return "allow"
	case strings.HasSuffix(action, "FAILURE"), strings.HasSuffix(action, "_DENY"):
		return "deny"
	default:
		return ""
	}
}

func sanitizePlainText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(trimmed))
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
