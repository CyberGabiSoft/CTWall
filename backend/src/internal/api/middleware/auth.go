package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

const (
	authMethodCookie = "cookie"
	authMethodToken  = "api_token"
)

// AuthConfig configures authentication middleware.
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

// AuthMiddleware authenticates requests and enforces roles.
type AuthMiddleware struct {
	store       store.Store
	config      AuthConfig
	logger      *slog.Logger
	auditWriter *audit.Writer
}

// NewAuthMiddleware builds a new auth middleware instance.
func NewAuthMiddleware(st store.Store, cfg AuthConfig) (*AuthMiddleware, error) {
	if st == nil {
		return nil, errors.New("store required")
	}
	if len(cfg.JWTSecret) == 0 {
		return nil, errors.New("JWT secret required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "__Host-CTWALL_SESSION"
	}
	return &AuthMiddleware{
		store:       st,
		config:      cfg,
		logger:      slog.Default().With("component", "middleware.auth"),
		auditWriter: cfg.AuditWriter,
	}, nil
}

// RequireRoles authenticates and checks whether the user has any of the provided roles.
func (a *AuthMiddleware) RequireRoles(roles ...auth.Role) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			userCtx, err := a.authenticate(r)
			if err != nil {
				writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.")
				return
			}
			if !auth.RoleAllowed(userCtx.Role, roles...) {
				a.auditDecision(r, userCtx, "AUTHZ_DENY", "role_denied")
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Insufficient permissions.")
				return
			}
			if userCtx.AuthMethod == authMethodCookie && RequiresXSRF(r) {
				if err := VerifyXSRF(r); err != nil {
					a.auditDecision(r, userCtx, "AUTHZ_DENY", xsrfReason(err))
					writeProblem(w, r, http.StatusForbidden, "Forbidden", "CSRF validation failed.")
					return
				}
			}

			a.auditDecision(r, userCtx, "AUTHZ_ALLOW", "")
			ctx := auth.WithUser(r.Context(), userCtx)
			next(w, r.WithContext(ctx))
		}
	}
}

func (a *AuthMiddleware) authenticate(r *http.Request) (auth.UserContext, error) {
	var cookieErr error
	if cookie, err := r.Cookie(a.config.CookieName); err == nil && strings.TrimSpace(cookie.Value) != "" {
		userCtx, err := a.authenticateJWT(r, cookie.Value)
		if err == nil {
			return userCtx, nil
		}
		a.logger.Warn("jwt authentication failed", "error", err)
		cookieErr = err
	}

	bearer := extractBearerToken(r.Header.Get("Authorization"))
	if bearer == "" {
		if cookieErr != nil {
			return auth.UserContext{}, cookieErr
		}
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "missing_token")
		return auth.UserContext{}, errors.New("missing auth")
	}

	userCtx, err := a.authenticateToken(r, bearer)
	if err != nil {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "invalid_token")
		return auth.UserContext{}, err
	}
	return userCtx, nil
}

func (a *AuthMiddleware) authenticateJWT(r *http.Request, token string) (auth.UserContext, error) {
	userID, role, err := auth.ParseSessionToken(token, a.config.JWTSecret, a.config.JWTIssuer)
	if err != nil {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "invalid_jwt")
		return auth.UserContext{}, err
	}
	user, err := a.store.GetUserByID(userID)
	if err != nil {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "user_not_found")
		return auth.UserContext{}, err
	}
	dbRole := auth.NormalizeRole(user.Role)
	if dbRole != role {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "role_mismatch")
		return auth.UserContext{}, errors.New("role mismatch")
	}
	accountType := auth.NormalizeAccountType(user.AccountType)
	if !auth.IsValidAccountType(string(accountType)) {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "invalid_account_type")
		return auth.UserContext{}, errors.New("invalid account type")
	}
	if accountType == auth.AccountTypeServiceAccount {
		a.auditDecision(r, auth.UserContext{}, "AUTHN_DENY", "service_account_cookie")
		return auth.UserContext{}, errors.New("service account login denied")
	}
	ctx := auth.UserContext{
		ID:          user.ID,
		Role:        dbRole,
		AccountType: accountType,
		Email:       user.Email,
		Nickname:    user.Nickname,
		FullName:    user.FullName,
		AuthMethod:  authMethodCookie,
	}
	a.auditDecision(r, ctx, "AUTHN_ALLOW", authMethodCookie)
	return ctx, nil
}

func (a *AuthMiddleware) authenticateToken(r *http.Request, token string) (auth.UserContext, error) {
	hash := auth.HashAPIToken(token)
	apiToken, user, err := a.store.GetAPITokenByHash(hash)
	if err != nil {
		return auth.UserContext{}, err
	}
	ctx := auth.UserContext{
		ID:          user.ID,
		Role:        auth.NormalizeRole(user.Role),
		AccountType: auth.NormalizeAccountType(user.AccountType),
		Email:       user.Email,
		Nickname:    user.Nickname,
		FullName:    user.FullName,
		AuthMethod:  authMethodToken,
	}
	if !auth.IsValidRole(string(ctx.Role)) {
		return auth.UserContext{}, errors.New("invalid role")
	}
	if !auth.IsValidAccountType(string(ctx.AccountType)) {
		return auth.UserContext{}, errors.New("invalid account type")
	}
	if apiToken != nil {
		tokenID := apiToken.ID
		ctx.TokenID = &tokenID
	}
	a.auditDecision(r, ctx, "AUTHN_ALLOW", authMethodToken)
	return ctx, nil
}

func extractBearerToken(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (a *AuthMiddleware) auditDecision(r *http.Request, user auth.UserContext, action string, reason string) {
	// Avoid flooding audit_logs with per-request "allow" decisions.
	// We persist only high-signal denies. Allows are still logged to the log stream.
	if action != "AUTHZ_DENY" && action != "AUTHN_DENY" {
		a.logger.Debug("auth decision", "action", action, "role", user.Role, "method", user.AuthMethod)
		return
	}

	category := eventmeta.CategoryAuthZ
	if strings.HasPrefix(strings.TrimSpace(action), "AUTHN_") {
		category = eventmeta.CategoryAuthN
	}
	traceID := TraceIDFromContext(r.Context())
	component := ComponentFromContext(r.Context())
	pattern := RoutePatternFromContext(r.Context())
	resourcePath := strings.TrimSpace(pattern)
	if resourcePath == "" && r != nil {
		resourcePath = strings.TrimSpace(r.URL.Path)
	}

	eventKey := ""
	// Minimal allowlist: authz denies are visible as Events (WARN) when user enables category.
	if action == "AUTHZ_DENY" && strings.TrimSpace(component) != "" {
		eventKey = "authz.deny." + strings.TrimSpace(component)
	}
	if strings.TrimSpace(eventKey) == "" {
		eventKey = eventmeta.DefaultEventKey(category, action)
	}

	base := audit.DetailsBase{
		Category:  category,
		Severity:  eventmeta.SeverityWarn,
		MinRole:   eventmeta.MinRoleWrite,
		EventKey:  eventKey,
		TraceID:   traceID,
		Title:     "Access denied",
		Message:   "Authorization denied for a protected action.",
		Component: component,
	}
	details, buildErr := audit.BuildDetails(base, map[string]any{
		"reason":      reason,
		"resource":    r.Method + " " + resourcePath,
		"status":      audit.DecisionStatus(action),
		"auth_method": user.AuthMethod,
	})
	if buildErr != nil {
		a.logger.Error("audit details build failed", "error", buildErr, "action", action)
		return
	}

	entry := store.AuditLogEntry{
		Action:     action,
		EntityType: "AUTH",
		IPAddress:  audit.IPFromRequest(r),
		Details:    details,
	}
	if user.ID != (uuid.UUID{}) {
		entry.ActorID = &user.ID
	}
	confidential := user.Role == auth.RoleAdmin
	if a.auditWriter != nil {
		a.auditWriter.Write(entry, confidential)
	} else if err := a.store.CreateAuditLog(entry); err != nil {
		a.logger.Error("audit log write failed", "error", err)
	}

	fields := []any{
		"action", action,
		"role", user.Role,
		"method", user.AuthMethod,
		"ip", entry.IPAddress,
	}
	if user.ID != (uuid.UUID{}) {
		fields = append(fields, "user_id", user.ID)
	}
	if reason != "" {
		fields = append(fields, "reason", reason)
	}
	if r != nil {
		fields = append(fields, "resource", r.Method+" "+r.URL.Path)
	}
	a.logger.Info("auth decision", fields...)
}

func xsrfReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, errXSRFCookieMissing):
		return "xsrf_cookie_missing"
	case errors.Is(err, errXSRFHeaderMissing):
		return "xsrf_header_missing"
	case errors.Is(err, errXSRFTokenMismatch):
		return "xsrf_token_mismatch"
	default:
		return "xsrf_invalid"
	}
}
