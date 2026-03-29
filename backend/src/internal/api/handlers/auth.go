package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

// AuthConfig configures auth handlers.
type AuthConfig struct {
	JWTSecret         []byte
	JWTIssuer         string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	CookieName        string
	RefreshCookieName string
	CookieSecure      bool
	AuditWriter       *audit.Writer
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

var (
	generateRefreshTokenFn = generateRefreshToken
	generateXSRFTokenFn    = generateXSRFToken
	hashPasswordFn         = auth.HashPassword
	xsrfRandRead           = rand.Read
)

// AuthLoginHandler authenticates a user and sets the session cookie.
func AuthLoginHandler(memStore store.Store, cfg AuthConfig) http.HandlerFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "__Host-CTWALL_SESSION"
	}
	if cfg.RefreshCookieName == "" {
		cfg.RefreshCookieName = "__Secure-CTWALL_REFRESH"
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 30 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 72 * time.Hour
	}
	return func(w http.ResponseWriter, r *http.Request) {
		auditLog := func(action string, actorID *uuid.UUID, reason string, confidential bool) {
			action = strings.TrimSpace(action)
			reason = strings.TrimSpace(reason)
			entry := store.AuditLogEntry{
				ActorID:    actorID,
				Action:     action,
				EntityType: "AUTH",
				IPAddress:  audit.IPFromRequest(r),
			}
			traceID := middleware.TraceIDFromContext(r.Context())
			component := middleware.ComponentFromContext(r.Context())
			pattern := middleware.RoutePatternFromContext(r.Context())
			resourcePath := strings.TrimSpace(pattern)
			if resourcePath == "" {
				resourcePath = strings.TrimSpace(r.URL.Path)
			}

			severity := eventmeta.SeverityInfo
			if strings.HasSuffix(action, "FAILURE") || strings.HasSuffix(action, "_DENY") {
				severity = eventmeta.SeverityWarn
			}
			eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryAuthN, action)
			title := "Auth event"
			message := "Authentication event recorded."
			if action == "LOGIN_FAILURE" {
				title = "Login failed"
				message = "Login failed."
				if reason != "" {
					eventKey = "authn.login_fail." + reason
					message = "Login failed: " + reason + "."
				}
			} else if action == "LOGIN_SUCCESS" {
				// Optional (INFO) event in Events UI when user enables INFO + authn category.
				// Keep the key low-cardinality (do not include user IDs, IPs, raw paths).
				eventKey = "authn.login_success"
				title = "Login success"
				message = "Login successful."
			}

			details, buildErr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryAuthN,
				Severity:  severity,
				MinRole:   eventmeta.MinRoleRead,
				EventKey:  eventKey,
				TraceID:   traceID,
				Title:     title,
				Message:   message,
				Component: component,
			}, map[string]any{
				"reason":   reason,
				"status":   audit.DecisionStatus(action),
				"resource": r.Method + " " + resourcePath,
			})
			if buildErr == nil {
				entry.Details = details
			}
			if cfg.AuditWriter != nil {
				cfg.AuditWriter.Write(entry, confidential)
				return
			}
			if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.auth.login", "error", err)
			}
		}

		var payload loginRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		email, err := validateEmail("email", payload.Email, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		password, err := validatePassword("password", payload.Password, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		creds, err := memStore.GetUserByEmail(email)
		if err != nil {
			slog.Warn("login failed", "component", "handler.auth.login", "email", audit.SanitizeLogValue(email), "reason", "user_not_found")
			auditLog("LOGIN_FAILURE", nil, "user_not_found", false)
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.", nil)
			return
		}
		isAdmin := auth.NormalizeRole(creds.User.Role) == auth.RoleAdmin
		valid, err := auth.VerifyPassword(password, creds.PasswordHash)
		if err != nil || !valid {
			slog.Warn("login failed", "component", "handler.auth.login", "email", audit.SanitizeLogValue(email), "reason", "invalid_credentials")
			actorID := creds.User.ID
			auditLog("LOGIN_FAILURE", &actorID, "invalid_credentials", isAdmin)
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.", nil)
			return
		}

		accountType := auth.NormalizeAccountType(creds.User.AccountType)
		if !auth.IsValidAccountType(string(accountType)) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Invalid account type.", errors.New("invalid account type"))
			return
		}
		if accountType == auth.AccountTypeServiceAccount {
			actorID := creds.User.ID
			auditLog("LOGIN_FAILURE", &actorID, "invalid_credentials", isAdmin)
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid credentials.", nil)
			return
		}

		role := auth.NormalizeRole(creds.User.Role)
		if !auth.IsValidRole(string(role)) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Invalid user role.", errors.New("invalid role"))
			return
		}
		token, err := auth.NewSessionToken(creds.User.ID, role, cfg.AccessTokenTTL, cfg.JWTSecret, cfg.JWTIssuer)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create session.", err)
			return
		}
		refreshToken, refreshHash, err := generateRefreshTokenFn()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create refresh token.", err)
			return
		}
		refreshExpiry := time.Now().UTC().Add(cfg.RefreshTokenTTL)
		userAgent := sanitizeUserAgent(r.UserAgent())
		ipAddress := audit.IPFromRequest(r)
		if _, err := memStore.CreateRefreshTokenAndRevokeOthers(creds.User.ID, refreshHash, refreshExpiry, userAgent, ipAddress); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to persist refresh token.", err)
			return
		}
		xsrfToken, err := generateXSRFTokenFn()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create security token.", err)
			return
		}
		actorID := creds.User.ID
		auditLog("LOGIN_SUCCESS", &actorID, "", isAdmin)

		http.SetCookie(w, &http.Cookie{
			Name:     cfg.CookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.AccessTokenTTL.Seconds()),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.RefreshCookieName,
			Value:    refreshToken,
			Path:     "/api/v1/auth/refresh",
			HttpOnly: true,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.RefreshTokenTTL.Seconds()),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     middleware.XSRFCookieName,
			Value:    xsrfToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.RefreshTokenTTL.Seconds()),
		})
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// AuthRefreshHandler rotates refresh tokens and issues a new access token.
func AuthRefreshHandler(memStore store.Store, cfg AuthConfig) http.HandlerFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "__Host-CTWALL_SESSION"
	}
	if cfg.RefreshCookieName == "" {
		cfg.RefreshCookieName = "__Secure-CTWALL_REFRESH"
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 30 * time.Minute
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = 72 * time.Hour
	}
	return func(w http.ResponseWriter, r *http.Request) {
		refreshCookie, err := r.Cookie(cfg.RefreshCookieName)
		if err != nil || strings.TrimSpace(refreshCookie.Value) == "" {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Refresh token required.", err)
			return
		}
		if err := middleware.VerifyXSRF(r); err != nil {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "CSRF validation failed.", err)
			return
		}

		newToken, newHash, err := generateRefreshTokenFn()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create refresh token.", err)
			return
		}
		newExpiry := time.Now().UTC().Add(cfg.RefreshTokenTTL)
		currentHash := auth.HashRefreshToken(refreshCookie.Value)
		userAgent := sanitizeUserAgent(r.UserAgent())
		ipAddress := audit.IPFromRequest(r)
		refreshed, user, err := memStore.RotateRefreshToken(currentHash, newHash, newExpiry, userAgent, ipAddress)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid refresh token.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to rotate refresh token.", err)
			return
		}

		accountType := auth.NormalizeAccountType(user.AccountType)
		if !auth.IsValidAccountType(string(accountType)) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Invalid account type.", errors.New("invalid account type"))
			return
		}
		if accountType == auth.AccountTypeServiceAccount {
			slog.Warn("refresh denied for service account", "component", "handler.auth.refresh", "user_id", user.ID)
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Invalid refresh token.", nil)
			return
		}

		role := auth.NormalizeRole(user.Role)
		if !auth.IsValidRole(string(role)) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Invalid user role.", errors.New("invalid role"))
			return
		}
		token, err := auth.NewSessionToken(user.ID, role, cfg.AccessTokenTTL, cfg.JWTSecret, cfg.JWTIssuer)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create session.", err)
			return
		}
		xsrfToken, err := generateXSRFTokenFn()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create security token.", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     cfg.CookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.AccessTokenTTL.Seconds()),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     cfg.RefreshCookieName,
			Value:    newToken,
			Path:     "/api/v1/auth/refresh",
			HttpOnly: true,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.RefreshTokenTTL.Seconds()),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     middleware.XSRFCookieName,
			Value:    xsrfToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   cfg.CookieSecure,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   int(cfg.RefreshTokenTTL.Seconds()),
		})
		slog.Debug("refresh token rotated", "component", "handler.auth.refresh", "token_id", refreshed.ID, "user_id", user.ID)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// AuthLogoutHandler revokes the refresh token (if present) and clears auth cookies.
func AuthLogoutHandler(memStore store.Store, cfg AuthConfig) http.HandlerFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "__Host-CTWALL_SESSION"
	}
	if cfg.RefreshCookieName == "" {
		cfg.RefreshCookieName = "__Secure-CTWALL_REFRESH"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.", errors.New("missing user context"))
			return
		}

		auditLog := func(action string, reason string) {
			action = strings.TrimSpace(action)
			reason = strings.TrimSpace(reason)
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     action,
				EntityType: "AUTH",
				IPAddress:  audit.IPFromRequest(r),
			}
			traceID := middleware.TraceIDFromContext(r.Context())
			component := middleware.ComponentFromContext(r.Context())
			pattern := middleware.RoutePatternFromContext(r.Context())
			resourcePath := strings.TrimSpace(pattern)
			if resourcePath == "" {
				resourcePath = strings.TrimSpace(r.URL.Path)
			}
			severity := eventmeta.SeverityInfo
			if strings.HasSuffix(action, "FAILURE") {
				severity = eventmeta.SeverityWarn
			}
			eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryAuthN, action)
			details, buildErr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryAuthN,
				Severity:  severity,
				MinRole:   eventmeta.MinRoleRead,
				EventKey:  eventKey,
				TraceID:   traceID,
				Title:     "Logout",
				Message:   "Logout event.",
				Component: component,
			}, map[string]any{
				"reason":   reason,
				"status":   audit.DecisionStatus(action),
				"resource": r.Method + " " + resourcePath,
			})
			if buildErr == nil {
				entry.Details = details
			}
			if cfg.AuditWriter != nil {
				cfg.AuditWriter.Write(entry, userCtx.Role == auth.RoleAdmin)
				return
			}
			if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.auth.logout", "error", err)
			}
		}

		if refreshCookie, err := r.Cookie(cfg.RefreshCookieName); err == nil && strings.TrimSpace(refreshCookie.Value) != "" {
			hash := auth.HashRefreshToken(refreshCookie.Value)
			if err := memStore.RevokeRefreshToken(hash); err != nil {
				auditLog("LOGOUT_FAILURE", "revoke_failed")
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to logout.", err)
				return
			}
		}

		clearAuthCookies(w, cfg)
		auditLog("LOGOUT_SUCCESS", "")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

// AuthChangePasswordHandler updates a user's password after verifying the current password.
func AuthChangePasswordHandler(memStore store.Store, cfg AuthConfig) http.HandlerFunc {
	if cfg.CookieName == "" {
		cfg.CookieName = "__Host-CTWALL_SESSION"
	}
	if cfg.RefreshCookieName == "" {
		cfg.RefreshCookieName = "__Secure-CTWALL_REFRESH"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.", errors.New("missing user context"))
			return
		}
		if userCtx.AccountType == auth.AccountTypeServiceAccount {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "Service accounts cannot change passwords.", nil)
			return
		}

		auditLog := func(action string, reason string) {
			action = strings.TrimSpace(action)
			reason = strings.TrimSpace(reason)
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     action,
				EntityType: "AUTH",
				IPAddress:  audit.IPFromRequest(r),
			}
			traceID := middleware.TraceIDFromContext(r.Context())
			component := middleware.ComponentFromContext(r.Context())
			pattern := middleware.RoutePatternFromContext(r.Context())
			resourcePath := strings.TrimSpace(pattern)
			if resourcePath == "" {
				resourcePath = strings.TrimSpace(r.URL.Path)
			}
			severity := eventmeta.SeverityInfo
			if strings.HasSuffix(action, "FAILURE") {
				severity = eventmeta.SeverityWarn
			}
			eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryAuthN, action)
			details, buildErr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryAuthN,
				Severity:  severity,
				MinRole:   eventmeta.MinRoleRead,
				EventKey:  eventKey,
				TraceID:   traceID,
				Title:     "Password change",
				Message:   "Password change event.",
				Component: component,
			}, map[string]any{
				"reason":   reason,
				"status":   audit.DecisionStatus(action),
				"resource": r.Method + " " + resourcePath,
			})
			if buildErr == nil {
				entry.Details = details
			}
			if cfg.AuditWriter != nil {
				cfg.AuditWriter.Write(entry, userCtx.Role == auth.RoleAdmin)
				return
			}
			if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.auth.change_password", "error", err)
			}
		}

		var payload changePasswordRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		currentPassword, err := validatePassword("currentPassword", payload.CurrentPassword, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		newPassword, err := validatePasswordStrength("newPassword", payload.NewPassword)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		creds, err := memStore.GetUserByEmail(userCtx.Email)
		if err != nil {
			auditLog("PASSWORD_CHANGE_FAILURE", "user_not_found")
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if creds == nil || creds.User.ID != userCtx.ID {
			auditLog("PASSWORD_CHANGE_FAILURE", "user_mismatch")
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", errors.New("user mismatch"))
			return
		}

		valid, err := auth.VerifyPassword(currentPassword, creds.PasswordHash)
		if err != nil || !valid {
			auditLog("PASSWORD_CHANGE_FAILURE", "invalid_current_password")
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "Invalid credentials.", nil)
			return
		}

		if same, _ := auth.VerifyPassword(newPassword, creds.PasswordHash); same {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "New password must be different from the current password.", nil)
			return
		}

		newHash, err := hashPasswordFn(newPassword)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if err := memStore.UpdateUserPassword(userCtx.ID, newHash); err != nil {
			auditLog("PASSWORD_CHANGE_FAILURE", "update_failed")
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if err := memStore.RevokeRefreshTokensForUser(userCtx.ID); err != nil {
			auditLog("PASSWORD_CHANGE_FAILURE", "revoke_failed")
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}

		clearAuthCookies(w, cfg)
		auditLog("PASSWORD_CHANGE_SUCCESS", "")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

// AuthMeHandler returns the current authenticated user.
func AuthMeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.", errors.New("missing user context"))
			return
		}
		resp := map[string]any{
			"id":          userCtx.ID,
			"email":       userCtx.Email,
			"role":        userCtx.Role,
			"accountType": userCtx.AccountType,
			"nickname":    userCtx.Nickname,
			"fullName":    userCtx.FullName,
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, resp)
	}
}

func generateRefreshToken() (string, string, error) {
	raw, err := generateToken()
	if err != nil {
		return "", "", err
	}
	return raw, auth.HashRefreshToken(raw), nil
}

func generateXSRFToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := xsrfRandRead(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func clearAuthCookies(w http.ResponseWriter, cfg AuthConfig) {
	clearCookie(w, cfg.CookieName, "/", cfg.CookieSecure, true)
	clearCookie(w, cfg.RefreshCookieName, "/api/v1/auth/refresh", cfg.CookieSecure, true)
	clearCookie(w, middleware.XSRFCookieName, "/", cfg.CookieSecure, false)
}

func clearCookie(w http.ResponseWriter, name, path string, secure, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
