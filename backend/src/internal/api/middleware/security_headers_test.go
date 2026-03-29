package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeadersApplied(t *testing.T) {
	handler := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("expected HSTS header")
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatalf("expected CSP header")
	}
	if got := recorder.Header().Get("Content-Security-Policy"); strings.Contains(got, "unsafe-inline") {
		t.Fatalf("expected CSP without unsafe-inline for API responses, got %q", got)
	}
	if got := recorder.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff header")
	}
	if got := recorder.Header().Get("Referrer-Policy"); got == "" {
		t.Fatalf("expected referrer policy header")
	}
	if got := recorder.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected x-frame-options deny")
	}
	if got := recorder.Header().Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Fatalf("expected coop header")
	}
	if got := recorder.Header().Get("Cross-Origin-Resource-Policy"); got != "same-site" {
		t.Fatalf("expected corp header")
	}
	if got := recorder.Header().Get("Permissions-Policy"); got == "" {
		t.Fatalf("expected permissions-policy header")
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected cache-control no-store")
	}
}

func TestSecurityHeadersNoHSTSWhenInsecure(t *testing.T) {
	handler := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("expected no HSTS header on insecure request")
	}
	if got := recorder.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("expected no cache-control header for non-API route")
	}
}

func TestSecurityHeaders_DoNotOverrideCSPIfSetByHandler(t *testing.T) {
	handler := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "custom-csp")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Content-Security-Policy"); got != "custom-csp" {
		t.Fatalf("expected handler CSP preserved, got %q", got)
	}
}

func TestSecurityHeaders_AppliedOnWritePath(t *testing.T) {
	handler := WithSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-Forwarded-Ssl", "on")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Strict-Transport-Security"); got == "" {
		t.Fatalf("expected HSTS header on secure request")
	}
	if got := recorder.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatalf("expected CSP header")
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected cache-control no-store, got %q", got)
	}
}

func TestSecurityHeaders_ApplyOnlyOnceAndNilRequestSafe(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &securityHeaderWriter{
		ResponseWriter: recorder,
		request:        nil,
	}

	writer.apply()
	writer.apply()
	if writer.wroteHeader != true {
		t.Fatalf("expected wroteHeader to remain true after repeated apply")
	}

	// Nil request should not panic and should not set headers.
	setSecurityHeaders(recorder, nil)
	if got := recorder.Header().Get("Content-Security-Policy"); got != "" {
		t.Fatalf("expected no CSP for nil request, got %q", got)
	}
}

func TestSecurityHeaders_IsSecureRequestViaTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/check", nil)
	req.TLS = &tls.ConnectionState{}
	if !isSecureRequest(req) {
		t.Fatalf("expected request with TLS state to be secure")
	}
}
