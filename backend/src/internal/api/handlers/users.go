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

type createUserRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	AccountType string `json:"accountType"`
	Nickname    string `json:"nickname"`
	FullName    string `json:"fullName"`
}

type createTokenRequest struct {
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt"`
}

type updateUserRequest struct {
	Role        string `json:"role"`
	AccountType string `json:"accountType"`
	Nickname    string `json:"nickname"`
	FullName    string `json:"fullName"`
}

type resetUserPasswordRequest struct {
	NewPassword string `json:"newPassword"`
}

var tokenRandRead = rand.Read

// ListUsersHandler returns the list of users (stub).
func ListUsersHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		users, err := memStore.ListUsers()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list users.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(users, page, pageSize))
	}
}

// CreateUserHandler creates a new user (admin only).
func CreateUserHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var payload createUserRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		email, err := validateEmail("email", payload.Email, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		password, err := validatePasswordStrength("password", payload.Password)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		role := auth.NormalizeRole(payload.Role)
		accountType := auth.NormalizeAccountType(payload.AccountType)
		nickname, err := validateNickname("nickname", payload.Nickname, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		fullName, err := validateFullName("fullName", payload.FullName)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if accountType == "" {
			accountType = auth.AccountTypeUser
		}
		if email == "" || password == "" || !auth.IsValidRole(string(role)) || !auth.IsValidAccountType(string(accountType)) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Email, password, valid role, and valid accountType are required.", nil)
			return
		}

		hash, err := auth.HashPassword(password)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to hash password.", err)
			return
		}

		user, err := memStore.CreateUser(email, hash, string(role), string(accountType), nickname, fullName)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "User already exists.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create user.", err)
			return
		}

		slog.Debug("user created", "component", "handler.users.create", "user_id", user.ID, "email", audit.SanitizeLogValue(email))
		writeJSON(w, http.StatusCreated, user)
	}
}

// UpdateUserHandler updates user profile fields (admin only).
func UpdateUserHandler(memStore store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("userId")
		userID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid userId.", err)
			return
		}

		var payload updateUserRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		role := auth.NormalizeRole(payload.Role)
		accountType := auth.NormalizeAccountType(payload.AccountType)
		nickname, err := validateNickname("nickname", payload.Nickname, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		fullName, err := validateFullName("fullName", payload.FullName)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if !auth.IsValidRole(string(role)) || !auth.IsValidAccountType(string(accountType)) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Valid role and accountType are required.", nil)
			return
		}

		updatedUser, err := memStore.UpdateUser(userID, string(role), string(accountType), nickname, fullName)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "User not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update user.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		action := "USER_UPDATE"
		eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryAccount, action)
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAccount,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  eventKey,
			TraceID:   traceID,
			Title:     "User updated",
			Message:   "Admin updated a user account.",
			Component: component,
		}, map[string]any{
			"targetUserId":      updatedUser.ID.String(),
			"targetEmail":       updatedUser.Email,
			"targetRole":        updatedUser.Role,
			"targetAccountType": updatedUser.AccountType,
		})
		if detailsErr != nil {
			slog.Error("audit details build failed", "component", "handler.users.update", "error", detailsErr)
		} else {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     action,
				EntityType: "USER",
				EntityID:   &updatedUser.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.users.update", "error", err)
			}
		}

		slog.Debug("user updated", "component", "handler.users.update", "user_id", updatedUser.ID, "email", audit.SanitizeLogValue(updatedUser.Email))
		writeJSON(w, http.StatusOK, updatedUser)
	}
}

// ResetUserPasswordHandler allows admin to set a new password for another USER account.
func ResetUserPasswordHandler(memStore store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := strings.TrimSpace(r.PathValue("userId"))
		userID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid userId.", err)
			return
		}
		if userID == userCtx.ID {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Use account change password for your own account.", nil)
			return
		}

		var payload resetUserPasswordRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		newPassword, err := validatePasswordStrength("newPassword", payload.NewPassword)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		target, err := memStore.GetUserByID(userID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "User not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load user.", err)
			return
		}
		if auth.NormalizeAccountType(target.AccountType) == auth.AccountTypeServiceAccount {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Service accounts cannot change passwords.", nil)
			return
		}

		creds, err := memStore.GetUserByEmail(target.Email)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if creds == nil || creds.User.ID != target.ID {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", errors.New("user credentials mismatch"))
			return
		}
		if same, _ := auth.VerifyPassword(newPassword, creds.PasswordHash); same {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "New password must be different from the current password.", nil)
			return
		}

		newHash, err := auth.HashPassword(newPassword)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if err := memStore.UpdateUserPassword(target.ID, newHash); err != nil {
			if err == store.ErrNotFound {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "User not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update password.", err)
			return
		}
		if err := memStore.RevokeRefreshTokensForUser(target.ID); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to revoke active sessions.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		action := "USER_PASSWORD_RESET"
		eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryAccount, action)
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAccount,
			Severity:  eventmeta.SeverityWarn,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  eventKey,
			TraceID:   traceID,
			Title:     "User password reset",
			Message:   "Admin reset a user password.",
			Component: component,
		}, map[string]any{
			"targetUserId":      target.ID.String(),
			"targetEmail":       target.Email,
			"targetRole":        target.Role,
			"targetAccountType": target.AccountType,
		})
		if detailsErr != nil {
			slog.Error("audit details build failed", "component", "handler.users.password_reset", "error", detailsErr)
		} else {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     action,
				EntityType: "USER",
				EntityID:   &target.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.users.password_reset", "error", err)
			}
		}

		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

// CreateUserTokenHandler generates an API token for a user.
func CreateUserTokenHandler(memStore store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.", errors.New("missing user context"))
			return
		}
		rawID := r.PathValue("userId")
		userID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid userId.", err)
			return
		}

		target, err := memStore.GetUserByID(userID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "User not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load user.", err)
			return
		}

		isSelf := userCtx.ID == userID
		isServiceAccount := auth.NormalizeAccountType(target.AccountType) == auth.AccountTypeServiceAccount
		adminForService := false
		if !isSelf {
			if userCtx.Role != auth.RoleAdmin || !isServiceAccount {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Cannot create token for another user.", nil)
				return
			}
			adminForService = true
		}

		var payload createTokenRequest
		if err := decodeOptionalJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		name, err := validateTokenName("name", payload.Name)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		if name == "" {
			name = "token-" + time.Now().UTC().Format("20060102-150405")
		}
		var expiresAt *time.Time
		if strings.TrimSpace(payload.ExpiresAt) != "" {
			parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(payload.ExpiresAt))
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid expiresAt format.", err)
				return
			}
			if parsed.Before(time.Now().UTC()) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "expiresAt must be in the future.", nil)
				return
			}
			expiresAt = &parsed
		}

		tokenPlain, err := generateToken()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to generate token.", err)
			return
		}
		hash := auth.HashAPIToken(tokenPlain)
		token, err := memStore.CreateAPIToken(userID, name, hash, expiresAt)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Token already exists.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create token.", err)
			return
		}

		if adminForService {
			traceID := middleware.TraceIDFromContext(r.Context())
			component := middleware.ComponentFromContext(r.Context())
			action := "TOKEN_CREATE_ADMIN"
			eventKey := eventmeta.DefaultEventKey(eventmeta.CategoryToken, action)
			details, err := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryToken,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleAdmin,
				EventKey:  eventKey,
				TraceID:   traceID,
				Title:     "Service account token created",
				Message:   "Admin created a token for a service account.",
				Component: component,
			}, map[string]any{
				"target_user_id": userID.String(),
				"account_type":   target.AccountType,
			})
			if err != nil {
				slog.Error("audit details build failed", "component", "handler.users.token", "error", err)
				details = nil
			}
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     action,
				EntityType: "API_TOKEN",
				EntityID:   &token.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			confidential := userCtx.Role == auth.RoleAdmin || auth.NormalizeRole(target.Role) == auth.RoleAdmin
			if auditWriter != nil {
				auditWriter.Write(entry, confidential)
			} else if err := memStore.CreateAuditLog(entry); err != nil {
				slog.Error("audit log write failed", "component", "handler.users.token", "error", err)
			}
		}

		response := map[string]any{
			"tokenId":   token.ID,
			"token":     tokenPlain,
			"name":      token.Name,
			"expiresAt": token.ExpiresAt,
			"createdAt": token.CreatedAt,
		}
		slog.Debug("user token created", "component", "handler.users.token", "token_id", token.ID, "user_id", userID)
		writeJSON(w, http.StatusCreated, response)
	}
}

// DeleteUserHandler deletes a user by ID.
func DeleteUserHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rawID := r.PathValue("userId")
		userID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid userId.", err)
			return
		}

		if err := memStore.DeleteUser(userID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "User not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete user.", err)
			return
		}

		slog.Debug("user deleted", "component", "handler.users.delete", "user_id", userID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := tokenRandRead(buf); err != nil {
		return "", err
	}
	return "ctw_live_" + hex.EncodeToString(buf), nil
}
