package middleware

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/core/auth"
	"backend/internal/tests"
)

func TestAuthMiddlewareCookie(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleAdmin, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret, JWTIssuer: "issuer"})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	called := false
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
		called = true
		ctxUser, ok := auth.UserFromContext(r.Context())
		if !ok || ctxUser.ID != user.ID {
			t.Fatalf("expected user context")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: token})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || !called {
		t.Fatalf("expected handler called")
	}
}

func TestAuthMiddlewareServiceAccountCookieDenied(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("svc@example.com", "hash", "ADMIN", "SERVICE_ACCOUNT", "Service")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleAdmin, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret, JWTIssuer: "issuer"})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
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

func TestAuthMiddlewareBearer(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("service@example.com", "hash", "WRITER", "SERVICE_ACCOUNT", "Service")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := "apitoken"
	hash := auth.HashAPIToken(token)
	if _, err := pgStore.CreateAPIToken(user.ID, "token", hash, nil); err != nil {
		t.Fatalf("create token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareXSRFRequiredForCookie(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleWriter, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret, JWTIssuer: "issuer"})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: token})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareXSRFAllowsCookie(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleWriter, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret, JWTIssuer: "issuer"})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: token})
	req.AddCookie(&http.Cookie{Name: XSRFCookieName, Value: "token"})
	req.Header.Set(XSRFHeaderName, "token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareMissing(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	details := fetchLatestAuditDetails(t, db)
	if details["resource"] != "GET /api/v1/products" || details["status"] != "deny" {
		t.Fatalf("unexpected audit details: %+v", details)
	}
}

func TestAuthMiddlewareForbidden(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "READER", "USER", "Viewer")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleReader, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: token})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareExpiredToken(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := auth.NewSessionToken(user.ID, auth.RoleAdmin, -time.Minute, []byte("secret"), "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
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

func fetchLatestAuditDetails(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(`SELECT details FROM audit_logs ORDER BY created_at DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatalf("audit logs query: %v", err)
	}
	var details map[string]string
	if err := json.Unmarshal(raw, &details); err != nil {
		t.Fatalf("audit details json: %v", err)
	}
	return details
}

func TestAuthMiddlewareRoleMismatch(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleAdmin, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	authMW, err := NewAuthMiddleware(pgStore, AuthConfig{JWTSecret: secret})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
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

func TestAuthMiddlewareInvalidRoleToken(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("service@example.com", "hash", "WRITER", "USER", "Service")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := "apitoken"
	hash := auth.HashAPIToken(token)
	apiToken, err := pgStore.CreateAPIToken(user.ID, "token", hash, nil)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	invalidUser := *user
	invalidUser.Role = "NOT_A_ROLE"
	wrapped := tests.StoreWrapper{
		Store:           pgStore,
		GetAPIToken:     apiToken,
		GetAPITokenUser: &invalidUser,
	}
	authMW, err := NewAuthMiddleware(wrapped, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestAuthMiddlewareInvalidAccountTypeCookie(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("user@example.com", "hash", "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("secret")
	token, err := auth.NewSessionToken(user.ID, auth.RoleAdmin, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	invalidUser := *user
	invalidUser.AccountType = "INVALID"
	wrapped := tests.StoreWrapper{Store: pgStore, GetUserByIDUser: &invalidUser}
	authMW, err := NewAuthMiddleware(wrapped, AuthConfig{JWTSecret: secret})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	handler := authMW.RequireRoles(auth.RoleAdmin)(func(w http.ResponseWriter, r *http.Request) {
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

func TestAuthMiddlewareInvalidAccountTypeBearer(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("service@example.com", "hash", "WRITER", "USER", "Service")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	token := "apitoken"
	hash := auth.HashAPIToken(token)
	apiToken, err := pgStore.CreateAPIToken(user.ID, "token", hash, nil)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	invalidUser := *user
	invalidUser.AccountType = "INVALID"
	wrapped := tests.StoreWrapper{
		Store:           pgStore,
		GetAPIToken:     apiToken,
		GetAPITokenUser: &invalidUser,
	}
	authMW, err := NewAuthMiddleware(wrapped, AuthConfig{JWTSecret: []byte("secret")})
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}

	handler := authMW.RequireRoles(auth.RoleWriter)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}
