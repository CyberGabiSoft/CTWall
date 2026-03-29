package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestAuthLoginHandler(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("user@example.com", hash, "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := AuthConfig{
		JWTSecret:         []byte("secret"),
		JWTIssuer:         "issuer",
		AccessTokenTTL:    15 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		CookieName:        "__Host-CTWALL_SESSION",
		RefreshCookieName: "__Secure-CTWALL_REFRESH",
		CookieSecure:      false,
	}
	handler := AuthLoginHandler(pgStore, cfg)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString("{bad"))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	payload := map[string]string{"email": "user@example.com", "password": "wrong"}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	payload = map[string]string{"email": "", "password": "secret"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing email, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	payload = map[string]string{"email": "user@example.com", "password": ""}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing password, got %d", recorder.Code)
	}

	oldToken := "old-refresh"
	if _, err := pgStore.CreateRefreshToken(user.ID, auth.HashRefreshToken(oldToken), time.Now().Add(24*time.Hour), "ua", "ip"); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	recorder = httptest.NewRecorder()
	payload = map[string]string{"email": "user@example.com", "password": "secret"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	cookies := recorder.Result().Cookies()
	sessionCookie := findCookie(cookies, cfg.CookieName)
	if sessionCookie == nil {
		t.Fatalf("expected session cookie")
	}
	refreshCookie := findCookie(cookies, cfg.RefreshCookieName)
	if refreshCookie == nil {
		t.Fatalf("expected refresh cookie")
	}
	xsrfCookie := findCookie(cookies, middleware.XSRFCookieName)
	if xsrfCookie == nil {
		t.Fatalf("expected xsrf cookie")
	}
	if refreshCookie.Path != "/api/v1/auth/refresh" {
		t.Fatalf("expected refresh cookie path")
	}

	var revokedAt sql.NullTime
	if err := db.QueryRow(
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashRefreshToken(oldToken),
	).Scan(&revokedAt); err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatalf("expected old refresh token revoked")
	}
}

func TestAuthLoginServiceAccountDenied(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	_, err = pgStore.CreateUser("svc@example.com", hash, "ADMIN", "SERVICE_ACCOUNT", "Service")
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}

	handler := AuthLoginHandler(pgStore, AuthConfig{JWTSecret: []byte("secret"), CookieSecure: false})
	payload := map[string]string{"email": "svc@example.com", "password": "secret"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	if len(recorder.Result().Cookies()) != 0 {
		t.Fatalf("expected no cookies for service account login")
	}
}

func TestAuthMeHandler(t *testing.T) {
	handler := AuthMeHandler()
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          uuid.New(),
		Role:        auth.RoleAdmin,
		AccountType: auth.AccountTypeUser,
		Email:       "user@example.com",
		FullName:    "User",
	})
	handler.ServeHTTP(recorder, req.WithContext(ctx))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestAuthLoginInvalidRole(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	creds := &store.UserCredentials{
		User: models.User{
			ID:          uuid.New(),
			Email:       "badrole@example.com",
			Role:        "NOT_A_ROLE",
			AccountType: "USER",
			FullName:    "User",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		PasswordHash: hash,
	}

	wrapped := tests.StoreWrapper{Store: pgStore, GetUserByEmailCreds: creds}
	handler := AuthLoginHandler(wrapped, AuthConfig{JWTSecret: []byte("secret"), CookieSecure: false})
	payload := map[string]string{"email": "badrole@example.com", "password": "secret"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestAuthRefreshHandler(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("user@example.com", hash, "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := AuthConfig{
		JWTSecret:         []byte("secret"),
		JWTIssuer:         "issuer",
		AccessTokenTTL:    10 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		CookieName:        "__Host-CTWALL_SESSION",
		RefreshCookieName: "__Secure-CTWALL_REFRESH",
		CookieSecure:      false,
	}
	handler := AuthRefreshHandler(pgStore, cfg)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing cookie, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: "invalid"})
	addXSRF(req, "token")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid cookie, got %d", recorder.Code)
	}

	rawToken := "ctw_refresh_token"
	if _, err := pgStore.CreateRefreshToken(user.ID, auth.HashRefreshToken(rawToken), time.Now().Add(24*time.Hour), "ua", "ip"); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: rawToken})
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing xsrf token, got %d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: rawToken})
	addXSRF(req, "token")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	cookies := recorder.Result().Cookies()
	sessionCookie := findCookie(cookies, cfg.CookieName)
	if sessionCookie == nil {
		t.Fatalf("expected session cookie")
	}
	refreshCookie := findCookie(cookies, cfg.RefreshCookieName)
	if refreshCookie == nil {
		t.Fatalf("expected refresh cookie")
	}
	xsrfCookie := findCookie(cookies, middleware.XSRFCookieName)
	if xsrfCookie == nil {
		t.Fatalf("expected xsrf cookie")
	}
	if refreshCookie.Value == rawToken {
		t.Fatalf("expected refresh token rotation")
	}

	var revokedAt sql.NullTime
	var replacedBy sql.NullString
	if err := db.QueryRow(
		`SELECT revoked_at, replaced_by_id FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashRefreshToken(rawToken),
	).Scan(&revokedAt, &replacedBy); err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if !revokedAt.Valid || !replacedBy.Valid {
		t.Fatalf("expected refresh token revoked and replaced")
	}
}

func TestAuthRefreshServiceAccountDenied(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("svc@example.com", hash, "ADMIN", "SERVICE_ACCOUNT", "Service")
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	rawToken := "svc_refresh_token"
	if _, err := pgStore.CreateRefreshToken(user.ID, auth.HashRefreshToken(rawToken), time.Now().Add(24*time.Hour), "ua", "ip"); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	handler := AuthRefreshHandler(pgStore, AuthConfig{JWTSecret: []byte("secret"), CookieSecure: false})
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "__Secure-CTWALL_REFRESH", Value: rawToken})
	addXSRF(req, "token")
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
}

func TestAuthLogoutHandler(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	hash, err := auth.HashPassword("Str0ng!Passw0rd")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("logout@example.com", hash, "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rawToken := "refresh-token"
	if _, err := pgStore.CreateRefreshToken(user.ID, auth.HashRefreshToken(rawToken), time.Now().Add(24*time.Hour), "ua", "ip"); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	cfg := AuthConfig{
		CookieName:        "__Host-CTWALL_SESSION",
		RefreshCookieName: "__Secure-CTWALL_REFRESH",
		CookieSecure:      false,
	}
	handler := AuthLogoutHandler(pgStore, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: rawToken})
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Role:        auth.RoleWriter,
		AccountType: auth.AccountTypeUser,
		Email:       user.Email,
	})
	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}

	cookies := recorder.Result().Cookies()
	if findCookie(cookies, cfg.CookieName) == nil {
		t.Fatalf("expected session cookie cleared")
	}
	if findCookie(cookies, cfg.RefreshCookieName) == nil {
		t.Fatalf("expected refresh cookie cleared")
	}
	if findCookie(cookies, middleware.XSRFCookieName) == nil {
		t.Fatalf("expected xsrf cookie cleared")
	}

	var revokedAt sql.NullTime
	if err := db.QueryRow(
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashRefreshToken(rawToken),
	).Scan(&revokedAt); err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatalf("expected refresh token revoked")
	}
}

func TestAuthChangePasswordHandler(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	oldPassword := "Str0ng!Passw0rd"
	newPassword := "An0ther!Passw0rd"
	hash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("change@example.com", hash, "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	rawToken := "refresh-change"
	if _, err := pgStore.CreateRefreshToken(user.ID, auth.HashRefreshToken(rawToken), time.Now().Add(24*time.Hour), "ua", "ip"); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	cfg := AuthConfig{
		CookieName:        "__Host-CTWALL_SESSION",
		RefreshCookieName: "__Secure-CTWALL_REFRESH",
		CookieSecure:      false,
	}
	handler := AuthChangePasswordHandler(pgStore, cfg)

	payload := map[string]string{"currentPassword": oldPassword, "newPassword": newPassword}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBuffer(body))
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Role:        auth.RoleWriter,
		AccountType: auth.AccountTypeUser,
		Email:       user.Email,
	})
	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}

	cookies := recorder.Result().Cookies()
	if findCookie(cookies, cfg.CookieName) == nil {
		t.Fatalf("expected session cookie cleared")
	}
	if findCookie(cookies, cfg.RefreshCookieName) == nil {
		t.Fatalf("expected refresh cookie cleared")
	}
	if findCookie(cookies, middleware.XSRFCookieName) == nil {
		t.Fatalf("expected xsrf cookie cleared")
	}

	creds, err := pgStore.GetUserByEmail(user.Email)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if creds == nil {
		t.Fatalf("expected credentials")
	}
	if valid, _ := auth.VerifyPassword(newPassword, creds.PasswordHash); !valid {
		t.Fatalf("expected updated password")
	}

	var activeCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`,
		user.ID,
	).Scan(&activeCount); err != nil {
		t.Fatalf("refresh token count: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("expected refresh tokens revoked")
	}
}

func TestAuthChangePasswordInvalidCurrent(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	oldPassword := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("badchange@example.com", hash, "WRITER", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	handler := AuthChangePasswordHandler(pgStore, AuthConfig{CookieSecure: false})
	payload := map[string]string{"currentPassword": "wrong", "newPassword": "An0ther!Passw0rd"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBuffer(body))
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Role:        auth.RoleWriter,
		AccountType: auth.AccountTypeUser,
		Email:       user.Email,
	})
	req = req.WithContext(ctx)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
	creds, err := pgStore.GetUserByEmail(user.Email)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	if valid, _ := auth.VerifyPassword(oldPassword, creds.PasswordHash); !valid {
		t.Fatalf("expected password unchanged")
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func addXSRF(req *http.Request, token string) {
	req.AddCookie(&http.Cookie{Name: middleware.XSRFCookieName, Value: token})
	req.Header.Set(middleware.XSRFHeaderName, token)
}
