package middleware

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

const (
	XSRFCookieName       = "__Host-XSRF-TOKEN"
	LegacyXSRFCookieName = "XSRF-TOKEN"
	XSRFHeaderName       = "X-XSRF-TOKEN"
)

var (
	errXSRFCookieMissing = errors.New("missing xsrf cookie")
	errXSRFHeaderMissing = errors.New("missing xsrf header")
	errXSRFTokenMismatch = errors.New("xsrf token mismatch")
)

// RequiresXSRF reports whether the request method is a state-changing method.
func RequiresXSRF(r *http.Request) bool {
	if r == nil {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// VerifyXSRF validates the double submit cookie token for browser sessions.
func VerifyXSRF(r *http.Request) error {
	if r == nil {
		return errors.New("request required")
	}
	cookie, err := r.Cookie(XSRFCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		cookie, err = r.Cookie(LegacyXSRFCookieName)
	}
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return errXSRFCookieMissing
	}
	header := strings.TrimSpace(r.Header.Get(XSRFHeaderName))
	if header == "" {
		return errXSRFHeaderMissing
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return errXSRFTokenMismatch
	}
	return nil
}
