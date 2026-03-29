package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDocsHandler_SetsNonceCSP_AndDoesNotUseUnsafeInline(t *testing.T) {
	orig := docsNonce
	t.Cleanup(func() { docsNonce = orig })
	docsNonce = func() (string, error) { return "testnonce", nil }

	handler := DocsHandler()
	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-testnonce") {
		t.Fatalf("expected CSP to include nonce, got %q", csp)
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("expected CSP without unsafe-inline, got %q", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `nonce="testnonce"`) {
		t.Fatalf("expected nonce attribute in HTML")
	}
}

