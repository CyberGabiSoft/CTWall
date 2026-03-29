package middleware

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestNewAuthMiddlewareValidationAndDefaults(t *testing.T) {
	if _, err := NewAuthMiddleware(nil, AuthConfig{JWTSecret: []byte("secret")}); err == nil {
		t.Fatalf("expected nil store validation error")
	}

	pgStore, _ := tests.NewPostgresTestStore(t)
	if _, err := NewAuthMiddleware(pgStore, AuthConfig{}); err == nil {
		t.Fatalf("expected jwt secret validation error")
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}
	if authMW.config.CookieName != "__Host-CTWALL_SESSION" {
		t.Fatalf("expected default cookie name, got %s", authMW.config.CookieName)
	}
}

func TestAuthMiddlewareJWTUserNotFound(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("secret")
	token, err := auth.NewSessionToken(uuid.New(), auth.RoleAdmin, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: token})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareBearerLookupError(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	wrapped := tests.StoreWrapper{
		Store:         pgStore,
		GetAPITokenErr: errors.New("lookup failed"),
	}
	authMW, err := NewAuthMiddleware(wrapped, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer api-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestExtractBearerTokenInvalidHeaders(t *testing.T) {
	if got := extractBearerToken("Token abc"); got != "" {
		t.Fatalf("expected empty token for invalid scheme, got %q", got)
	}
	if got := extractBearerToken("Bearer"); got != "" {
		t.Fatalf("expected empty token for missing value, got %q", got)
	}
}

func TestAuditDecisionAuthzDenyWithComponentEventKey(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	ctx := context.WithValue(req.Context(), componentKey, "handler.products.list")
	ctx = context.WithValue(ctx, routePatternKey, "/api/v1/products")
	req = req.WithContext(ctx)

	authMW.auditDecision(req, auth.UserContext{}, "AUTHZ_DENY", "role_denied")
	details := fetchLatestAuditDetails(t, db)
	if details["event_key"] != "authz.deny.handler.products.list" {
		t.Fatalf("expected authz component event key, got %+v", details)
	}
}

func TestAuditDecisionBuildDetailsErrorBranch(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	ctx := context.WithValue(req.Context(), componentKey, "invalid component key")
	req = req.WithContext(ctx)

	authMW.auditDecision(req, auth.UserContext{}, "AUTHZ_DENY", "role_denied")

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count); err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no persisted audit entries for invalid event key, got %d", count)
	}
}

func TestAuditDecisionUsesAuditWriterWhenConfigured(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	writer := audit.NewWriter(pgStore, audit.Config{StoreAllLogs: true}, nil)
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{
		JWTSecret:   []byte("secret"),
		AuditWriter: writer,
	})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	authMW.auditDecision(req, auth.UserContext{}, "AUTHN_DENY", "missing_token")

	details := fetchLatestAuditDetails(t, db)
	if details["status"] != "deny" {
		t.Fatalf("expected deny audit log via writer, got %+v", details)
	}
}

func TestAuditDecisionStoreWriteErrorBranch(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("new auth middleware: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	// Use unknown actor ID to trigger FK error in CreateAuditLog and cover error branch.
	authMW.auditDecision(req, auth.UserContext{ID: uuid.New()}, "AUTHN_DENY", "missing_token")
}

func TestXSRFReasonCoversAllBranches(t *testing.T) {
	if got := xsrfReason(nil); got != "" {
		t.Fatalf("expected empty reason for nil error, got %q", got)
	}
	if got := xsrfReason(errXSRFCookieMissing); got != "xsrf_cookie_missing" {
		t.Fatalf("unexpected reason for missing cookie: %q", got)
	}
	if got := xsrfReason(errXSRFHeaderMissing); got != "xsrf_header_missing" {
		t.Fatalf("unexpected reason for missing header: %q", got)
	}
	if got := xsrfReason(errXSRFTokenMismatch); got != "xsrf_token_mismatch" {
		t.Fatalf("unexpected reason for mismatch: %q", got)
	}
	if got := xsrfReason(sql.ErrNoRows); got != "xsrf_invalid" {
		t.Fatalf("unexpected reason for unknown error: %q", got)
	}
}
