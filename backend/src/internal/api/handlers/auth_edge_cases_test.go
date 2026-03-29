package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

type authEdgeStore struct {
	tests.StoreWrapper

	rotateRefreshTokenFn func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error)
	createAuditLogFn     func(entry store.AuditLogEntry) error
}

func (s authEdgeStore) RotateRefreshToken(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
	if s.rotateRefreshTokenFn != nil {
		return s.rotateRefreshTokenFn(currentHash, newHash, newExpiresAt, userAgent, ipAddress)
	}
	return s.StoreWrapper.Store.RotateRefreshToken(currentHash, newHash, newExpiresAt, userAgent, ipAddress)
}

func (s authEdgeStore) CreateAuditLog(entry store.AuditLogEntry) error {
	if s.createAuditLogFn != nil {
		return s.createAuditLogFn(entry)
	}
	return s.StoreWrapper.Store.CreateAuditLog(entry)
}

func authTestConfig() AuthConfig {
	return AuthConfig{
		JWTSecret:         []byte("secret"),
		JWTIssuer:         "issuer",
		AccessTokenTTL:    10 * time.Minute,
		RefreshTokenTTL:   24 * time.Hour,
		CookieName:        "__Host-CTWALL_SESSION",
		RefreshCookieName: "__Secure-CTWALL_REFRESH",
		CookieSecure:      false,
	}
}

func authJSONRequest(t *testing.T, method, path string, payload any) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return httptest.NewRequest(method, path, bytes.NewBuffer(body))
}

func createAuthUser(t *testing.T, st store.Store, email, password string, role auth.Role, accountType auth.AccountType) *models.User {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := st.CreateUser(email, hash, string(role), string(accountType), "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func withAuthUser(req *http.Request, user *models.User, role auth.Role, accountType auth.AccountType) *http.Request {
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Email:       user.Email,
		Role:        role,
		AccountType: accountType,
		FullName:    user.FullName,
	})
	return req.WithContext(ctx)
}

func withAuthTestSeams(t *testing.T) {
	t.Helper()
	originalGenerateRefreshTokenFn := generateRefreshTokenFn
	originalGenerateXSRFTokenFn := generateXSRFTokenFn
	originalHashPasswordFn := hashPasswordFn
	originalTokenRandRead := tokenRandRead
	originalXSRFRandRead := xsrfRandRead
	t.Cleanup(func() {
		generateRefreshTokenFn = originalGenerateRefreshTokenFn
		generateXSRFTokenFn = originalGenerateXSRFTokenFn
		hashPasswordFn = originalHashPasswordFn
		tokenRandRead = originalTokenRandRead
		xsrfRandRead = originalXSRFRandRead
	})
}

func TestAuthLoginHandlerEdgeCases(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	cfg := authTestConfig()

	t.Run("user not found returns unauthorized", func(t *testing.T) {
		handler := AuthLoginHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    "missing-" + uuid.NewString() + "@example.com",
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("invalid account type returns internal error", func(t *testing.T) {
		hash, err := auth.HashPassword("Str0ng!Passw0rd")
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store: pgStore,
				GetUserByEmailCreds: &store.UserCredentials{
					User: models.User{
						ID:          uuid.New(),
						Email:       "invalid-account@example.com",
						Role:        string(auth.RoleWriter),
						AccountType: "BROKEN",
						FullName:    "Broken",
						CreatedAt:   time.Now(),
						UpdatedAt:   time.Now(),
					},
					PasswordHash: hash,
				},
			},
		}
		handler := AuthLoginHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    "invalid-account@example.com",
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("session creation fails for empty jwt secret", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "login-empty-secret-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		_ = user
		cfgNoSecret := cfg
		cfgNoSecret.JWTSecret = nil
		handler := AuthLoginHandler(pgStore, cfgNoSecret)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    user.Email,
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("refresh token generation error returns internal error", func(t *testing.T) {
		withAuthTestSeams(t)
		user := createAuthUser(t, pgStore, "login-refresh-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		generateRefreshTokenFn = func() (string, string, error) {
			return "", "", errors.New("refresh generation failed")
		}
		handler := AuthLoginHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    user.Email,
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("persist refresh token failure returns internal error", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "login-refresh-store-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store:                          pgStore,
				CreateRefreshTokenAndRevokeErr: errors.New("persist failed"),
			},
		}
		handler := AuthLoginHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    user.Email,
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("xsrf generation error returns internal error", func(t *testing.T) {
		withAuthTestSeams(t)
		user := createAuthUser(t, pgStore, "login-xsrf-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		generateXSRFTokenFn = func() (string, error) {
			return "", errors.New("xsrf generation failed")
		}
		handler := AuthLoginHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    user.Email,
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("audit writer path is used when configured", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "login-audit-writer-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleAdmin, auth.AccountTypeUser)
		cfgWithAuditWriter := cfg
		cfgWithAuditWriter.AuditWriter = audit.NewWriter(nil, audit.Config{}, nil)
		handler := AuthLoginHandler(pgStore, cfgWithAuditWriter)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    user.Email,
			"password": "wrong-password",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("audit log write failure is tolerated", func(t *testing.T) {
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			createAuditLogFn: func(entry store.AuditLogEntry) error {
				return errors.New("audit write failed")
			},
		}
		handler := AuthLoginHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/login", map[string]string{
			"email":    "missing-audit-" + uuid.NewString() + "@example.com",
			"password": "Str0ng!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}

func TestAuthRefreshHandlerEdgeCases(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	cfg := authTestConfig()

	makeRefreshRequest := func(refreshToken string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
		req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: refreshToken})
		addXSRF(req, "token")
		return req
	}

	t.Run("refresh token generation error returns internal error", func(t *testing.T) {
		withAuthTestSeams(t)
		generateRefreshTokenFn = func() (string, string, error) {
			return "", "", errors.New("refresh generation failed")
		}
		handler := AuthRefreshHandler(pgStore, cfg)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("rotate refresh token store error returns internal error", func(t *testing.T) {
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			rotateRefreshTokenFn: func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
				return nil, nil, errors.New("rotate failed")
			},
		}
		handler := AuthRefreshHandler(wrapped, cfg)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("invalid account type in refresh flow returns internal error", func(t *testing.T) {
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			rotateRefreshTokenFn: func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
				return &store.RefreshToken{ID: uuid.New()}, &models.User{
					ID:          uuid.New(),
					Role:        string(auth.RoleReader),
					AccountType: "BROKEN",
				}, nil
			},
		}
		handler := AuthRefreshHandler(wrapped, cfg)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("invalid role in refresh flow returns internal error", func(t *testing.T) {
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			rotateRefreshTokenFn: func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
				return &store.RefreshToken{ID: uuid.New()}, &models.User{
					ID:          uuid.New(),
					Role:        "BROKEN",
					AccountType: string(auth.AccountTypeUser),
				}, nil
			},
		}
		handler := AuthRefreshHandler(wrapped, cfg)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("session creation fails for empty jwt secret", func(t *testing.T) {
		cfgNoSecret := cfg
		cfgNoSecret.JWTSecret = nil
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			rotateRefreshTokenFn: func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
				return &store.RefreshToken{ID: uuid.New()}, &models.User{
					ID:          uuid.New(),
					Role:        string(auth.RoleWriter),
					AccountType: string(auth.AccountTypeUser),
				}, nil
			},
		}
		handler := AuthRefreshHandler(wrapped, cfgNoSecret)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("xsrf generation error returns internal error", func(t *testing.T) {
		withAuthTestSeams(t)
		generateXSRFTokenFn = func() (string, error) {
			return "", errors.New("xsrf generation failed")
		}
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			rotateRefreshTokenFn: func(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, *models.User, error) {
				return &store.RefreshToken{ID: uuid.New()}, &models.User{
					ID:          uuid.New(),
					Role:        string(auth.RoleWriter),
					AccountType: string(auth.AccountTypeUser),
				}, nil
			},
		}
		handler := AuthRefreshHandler(wrapped, cfg)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, makeRefreshRequest("any"))
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})
}

func TestAuthLogoutHandlerEdgeCases(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	t.Run("default cookie names are applied", func(t *testing.T) {
		cfg := AuthConfig{CookieSecure: false}
		handler := AuthLogoutHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "logout-default-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
		cookies := rec.Result().Cookies()
		if findCookie(cookies, "__Host-CTWALL_SESSION") == nil {
			t.Fatalf("expected default session cookie cleared")
		}
		if findCookie(cookies, "__Secure-CTWALL_REFRESH") == nil {
			t.Fatalf("expected default refresh cookie cleared")
		}
	})

	t.Run("missing user context returns unauthorized", func(t *testing.T) {
		handler := AuthLogoutHandler(pgStore, authTestConfig())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("revoke refresh token failure returns internal error", func(t *testing.T) {
		cfg := authTestConfig()
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store:                 pgStore,
				RevokeRefreshTokenErr: errors.New("revoke failed"),
			},
		}
		handler := AuthLogoutHandler(wrapped, cfg)
		user := createAuthUser(t, pgStore, "logout-revoke-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req.AddCookie(&http.Cookie{Name: cfg.RefreshCookieName, Value: "refresh-token"})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("audit writer branch is used when configured", func(t *testing.T) {
		cfg := authTestConfig()
		cfg.AuditWriter = audit.NewWriter(nil, audit.Config{}, nil)
		handler := AuthLogoutHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "logout-audit-writer-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleAdmin, auth.AccountTypeUser)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req = withAuthUser(req, user, auth.RoleAdmin, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})

	t.Run("audit write failure is tolerated", func(t *testing.T) {
		cfg := authTestConfig()
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			createAuditLogFn: func(entry store.AuditLogEntry) error {
				return errors.New("audit write failed")
			},
		}
		handler := AuthLogoutHandler(wrapped, cfg)
		user := createAuthUser(t, pgStore, "logout-audit-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})
}

func TestAuthChangePasswordHandlerEdgeCases(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	cfg := authTestConfig()

	t.Run("missing user context returns unauthorized", func(t *testing.T) {
		handler := AuthChangePasswordHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("service account cannot change password", func(t *testing.T) {
		handler := AuthChangePasswordHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "change-svc-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeServiceAccount)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeServiceAccount)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("invalid json returns bad request", func(t *testing.T) {
		handler := AuthChangePasswordHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "change-json-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", bytes.NewBufferString("{bad"))
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("invalid current password payload returns bad request", func(t *testing.T) {
		handler := AuthChangePasswordHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "change-current-invalid-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("weak new password returns bad request", func(t *testing.T) {
		handler := AuthChangePasswordHandler(pgStore, cfg)
		user := createAuthUser(t, pgStore, "change-weak-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "weak",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("get user by email error returns internal error", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-user-load-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store:             pgStore,
				GetUserByEmailErr: errors.New("load user failed"),
			},
		}
		handler := AuthChangePasswordHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("user mismatch returns internal error", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-mismatch-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		hash, err := auth.HashPassword("Str0ng!Passw0rd")
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store: pgStore,
				GetUserByEmailCreds: &store.UserCredentials{
					User: models.User{
						ID:          uuid.New(),
						Email:       user.Email,
						Role:        string(auth.RoleWriter),
						AccountType: string(auth.AccountTypeUser),
						FullName:    "Mismatch",
						CreatedAt:   time.Now(),
						UpdatedAt:   time.Now(),
					},
					PasswordHash: hash,
				},
			},
		}
		handler := AuthChangePasswordHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("new password same as current returns bad request", func(t *testing.T) {
		password := "Str0ng!Passw0rd"
		user := createAuthUser(t, pgStore, "change-same-"+uuid.NewString()+"@example.com", password, auth.RoleWriter, auth.AccountTypeUser)
		handler := AuthChangePasswordHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": password,
			"newPassword":     password,
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("hash password failure returns internal error", func(t *testing.T) {
		withAuthTestSeams(t)
		user := createAuthUser(t, pgStore, "change-hash-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		hashPasswordFn = func(password string) (string, error) {
			return "", errors.New("hash failed")
		}
		handler := AuthChangePasswordHandler(pgStore, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("update password failure returns internal error", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-update-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store:                 pgStore,
				UpdateUserPasswordErr: errors.New("update failed"),
			},
		}
		handler := AuthChangePasswordHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("revoke refresh tokens failure returns internal error", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-revoke-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{
				Store:                  pgStore,
				RevokeRefreshTokensErr: errors.New("revoke failed"),
			},
		}
		handler := AuthChangePasswordHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "Str0ng!Passw0rd",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("audit writer path is used in change password flow", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-audit-writer-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleAdmin, auth.AccountTypeUser)
		cfgWithAuditWriter := cfg
		cfgWithAuditWriter.AuditWriter = audit.NewWriter(nil, audit.Config{}, nil)
		handler := AuthChangePasswordHandler(pgStore, cfgWithAuditWriter)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "wrong-password",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleAdmin, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("audit log write failure is tolerated in change password flow", func(t *testing.T) {
		user := createAuthUser(t, pgStore, "change-audit-fail-"+uuid.NewString()+"@example.com", "Str0ng!Passw0rd", auth.RoleWriter, auth.AccountTypeUser)
		wrapped := authEdgeStore{
			StoreWrapper: tests.StoreWrapper{Store: pgStore},
			createAuditLogFn: func(entry store.AuditLogEntry) error {
				return errors.New("audit write failed")
			},
		}
		handler := AuthChangePasswordHandler(wrapped, cfg)
		req := authJSONRequest(t, http.MethodPost, "/api/v1/auth/change-password", map[string]string{
			"currentPassword": "wrong-password",
			"newPassword":     "An0ther!Passw0rd",
		})
		req = withAuthUser(req, user, auth.RoleWriter, auth.AccountTypeUser)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})
}

func TestAuthTokenHelpersEntropyErrors(t *testing.T) {
	withAuthTestSeams(t)

	t.Run("generate refresh token propagates entropy errors", func(t *testing.T) {
		tokenRandRead = func(buf []byte) (int, error) {
			return 0, errors.New("entropy unavailable")
		}
		if _, _, err := generateRefreshToken(); err == nil {
			t.Fatalf("expected refresh token error")
		}
	})

	t.Run("generate xsrf token propagates entropy errors", func(t *testing.T) {
		xsrfRandRead = func(buf []byte) (int, error) {
			return 0, errors.New("entropy unavailable")
		}
		if _, err := generateXSRFToken(); err == nil {
			t.Fatalf("expected xsrf token error")
		}
	})
}
