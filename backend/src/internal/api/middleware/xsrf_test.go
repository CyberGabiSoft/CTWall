package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequiresXSRF(t *testing.T) {
	if RequiresXSRF(nil) {
		t.Fatalf("expected nil request to not require xsrf")
	}

	if !RequiresXSRF(httptest.NewRequest(http.MethodPost, "/", nil)) {
		t.Fatalf("expected POST to require xsrf")
	}
	if !RequiresXSRF(httptest.NewRequest(http.MethodPut, "/", nil)) {
		t.Fatalf("expected PUT to require xsrf")
	}
	if !RequiresXSRF(httptest.NewRequest(http.MethodPatch, "/", nil)) {
		t.Fatalf("expected PATCH to require xsrf")
	}
	if !RequiresXSRF(httptest.NewRequest(http.MethodDelete, "/", nil)) {
		t.Fatalf("expected DELETE to require xsrf")
	}
	if RequiresXSRF(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatalf("expected GET to not require xsrf")
	}
}

func TestVerifyXSRF(t *testing.T) {
	if err := VerifyXSRF(nil); err == nil {
		t.Fatalf("expected nil request error")
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := VerifyXSRF(req); err != errXSRFCookieMissing {
		t.Fatalf("expected missing cookie error, got %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "   "})
	if err := VerifyXSRF(req); err != errXSRFCookieMissing {
		t.Fatalf("expected blank cookie error, got %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "token"})
	if err := VerifyXSRF(req); err != errXSRFHeaderMissing {
		t.Fatalf("expected missing header error, got %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "token"})
	req.Header.Set(XSRFHeaderName, "other")
	if err := VerifyXSRF(req); err != errXSRFTokenMismatch {
		t.Fatalf("expected mismatch error, got %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "token"})
	req.Header.Set(XSRFHeaderName, "token")
	if err := VerifyXSRF(req); err != nil {
		t.Fatalf("expected valid xsrf, got %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: LegacyXSRFCookieName, Value: "token"})
	req.Header.Set(XSRFHeaderName, "token")
	if err := VerifyXSRF(req); err != nil {
		t.Fatalf("expected valid legacy xsrf cookie, got %v", err)
	}
}
