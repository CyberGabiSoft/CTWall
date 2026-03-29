package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/core/auth"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestCreateUserHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := CreateUserHandler(pgStore)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBufferString("{bad"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload := map[string]string{"email": " ", "password": "x", "role": "ADMIN"}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"email": "user@example.com", "password": "secret", "role": "INVALID"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"email": "user@example.com", "password": "secret", "role": "ADMIN", "accountType": "INVALID"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"email": "user@example.com", "password": "weakpass", "role": "ADMIN", "nickname": "user-admin"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"email": "user@example.com", "password": "Str0ng!Passw0rd", "role": "ADMIN", "nickname": "user-admin"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}

	payload = map[string]string{"email": "none@example.com", "password": "Str0ng!Passw0rd", "role": "NONE", "nickname": "none-user"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201 for NONE role, got %d", recorder.Code)
	}
}

func TestUpdateUserHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := UpdateUserHandler(pgStore, nil)

	hash, err := auth.HashPassword("Str0ng!Passw0rd")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	admin, err := pgStore.CreateUser("admin@example.com", hash, "ADMIN", "USER", "Admin")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	target, err := pgStore.CreateUser("target@example.com", hash, "READER", "USER", "Target User")
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", nil)
	req.SetPathValue("userId", target.ID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", nil)
	req.SetPathValue("userId", "bad")
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBufferString("{bad"))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ := json.Marshal(map[string]string{
		"role":        "INVALID",
		"accountType": "USER",
		"nickname":    "invalid-role",
	})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBuffer(body))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]string{
		"role":        "WRITER",
		"accountType": "USER",
		"nickname":    "missing-user",
	})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBuffer(body))
	req.SetPathValue("userId", uuid.New().String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]string{
		"email":       "modified@example.com",
		"role":        "WRITER",
		"accountType": "USER",
		"nickname":    "conflict-user",
		"fullName":    "Conflict User",
	})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBuffer(body))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]string{
		"role":        "WRITER",
		"accountType": "SERVICE_ACCOUNT",
		"nickname":    "updated-target",
		"fullName":    "Updated Target",
	})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBuffer(body))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var updated struct {
		ID          uuid.UUID `json:"id"`
		Email       string    `json:"email"`
		Role        string    `json:"role"`
		AccountType string    `json:"accountType"`
		Nickname    string    `json:"nickname"`
		FullName    string    `json:"fullName"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if updated.ID != target.ID || updated.Email != "target@example.com" || updated.Role != "WRITER" {
		t.Fatalf("unexpected updated payload: %+v", updated)
	}
	if updated.AccountType != string(auth.AccountTypeServiceAccount) || updated.FullName != "Updated Target" {
		t.Fatalf("unexpected account update: %+v", updated)
	}
	if updated.Nickname != "updated-target" {
		t.Fatalf("expected nickname to be updated, got %q", updated.Nickname)
	}

	body, _ = json.Marshal(map[string]string{
		"role":        "NONE",
		"accountType": "USER",
		"nickname":    "no-access-user",
		"fullName":    "No Access User",
	})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/users/id", bytes.NewBuffer(body))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for NONE role update, got %d", recorder.Code)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if updated.Role != "NONE" {
		t.Fatalf("expected updated role NONE, got %q", updated.Role)
	}
	projects, err := pgStore.ListProjectsForUser(target.ID, false)
	if err != nil {
		t.Fatalf("list projects for updated user: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("expected no project access after NONE role update, got %d", len(projects))
	}

	logs, err := pgStore.ListAuditLogsByActionAndDetail("USER", &target.ID, "USER_UPDATE", "event_key", "account.user_update", 20, 0)
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if len(logs) == 0 {
		t.Fatalf("expected USER_UPDATE audit log")
	}
	var details map[string]any
	if err := json.Unmarshal(logs[0].Details, &details); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if got, _ := details["category"].(string); got != "account" {
		t.Fatalf("expected category=account, got %q", got)
	}
	if got, _ := details["severity"].(string); got != "INFO" {
		t.Fatalf("expected severity=INFO, got %q", got)
	}
	if got, _ := details["min_role"].(string); got != "admin" {
		t.Fatalf("expected min_role=admin, got %q", got)
	}
	if got, _ := details["event_key"].(string); got != "account.user_update" {
		t.Fatalf("expected event_key=account.user_update, got %q", got)
	}
}

func TestResetUserPasswordHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := ResetUserPasswordHandler(pgStore, nil)

	hash, err := auth.HashPassword("Str0ng!Passw0rd")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	admin, err := pgStore.CreateUser("admin-reset@example.com", hash, "ADMIN", "USER", "Admin Reset")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	target, err := pgStore.CreateUser("target-reset@example.com", hash, "READER", "USER", "Target Reset")
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	service, err := pgStore.CreateUser("service-reset@example.com", hash, "WRITER", "SERVICE_ACCOUNT", "Service Reset")
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Pass"}`))
	req.SetPathValue("userId", target.ID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Pass"}`))
	req.SetPathValue("userId", "bad")
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad id, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString("{bad"))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid json, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"weak"}`))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak password, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Pass"}`))
	req.SetPathValue("userId", uuid.New().String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing user, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Pass"}`))
	req.SetPathValue("userId", admin.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for self reset, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Pass"}`))
	req.SetPathValue("userId", service.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409 for service account, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"Str0ng!Passw0rd"}`))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for identical password, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/password", bytes.NewBufferString(`{"newPassword":"An0ther!Passw0rd"}`))
	req.SetPathValue("userId", target.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: admin.ID, Role: auth.RoleAdmin, Email: admin.Email}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}

	creds, err := pgStore.GetUserByEmail(target.Email)
	if err != nil {
		t.Fatalf("get target creds: %v", err)
	}
	if creds == nil {
		t.Fatalf("expected target credentials")
	}
	validOld, err := auth.VerifyPassword("Str0ng!Passw0rd", creds.PasswordHash)
	if err != nil {
		t.Fatalf("verify old password: %v", err)
	}
	if validOld {
		t.Fatalf("expected old password to be rejected")
	}
	validNew, err := auth.VerifyPassword("An0ther!Passw0rd", creds.PasswordHash)
	if err != nil {
		t.Fatalf("verify new password: %v", err)
	}
	if !validNew {
		t.Fatalf("expected new password to verify")
	}

	logs, err := pgStore.ListAuditLogsByActionAndDetail("USER", &target.ID, "USER_PASSWORD_RESET", "event_key", "account.user_password_reset", 20, 0)
	if err != nil {
		t.Fatalf("list audit logs: %v", err)
	}
	if len(logs) == 0 {
		t.Fatalf("expected USER_PASSWORD_RESET audit log")
	}
	var details map[string]any
	if err := json.Unmarshal(logs[0].Details, &details); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if got, _ := details["event_key"].(string); got != "account.user_password_reset" {
		t.Fatalf("expected event_key=account.user_password_reset, got %q", got)
	}
	if got, _ := details["severity"].(string); got != "WARN" {
		t.Fatalf("expected severity=WARN, got %q", got)
	}
}

func TestCreateUserTokenHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := CreateUserTokenHandler(pgStore, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/bad/tokens", nil)
	req.SetPathValue("userId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}

	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("token@example.com", hash, "ADMIN", string(auth.AccountTypeUser), "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	other, err := pgStore.CreateUser("other@example.com", hash, "WRITER", string(auth.AccountTypeUser), "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	service, err := pgStore.CreateUser("service@example.com", hash, "WRITER", string(auth.AccountTypeServiceAccount), "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/bad/tokens", nil)
	req.SetPathValue("userId", "bad")
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/missing/tokens", nil)
	req.SetPathValue("userId", uuid.New().String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBufferString(`{}`))
	req.SetPathValue("userId", other.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBufferString("{bad"))
	req.SetPathValue("userId", service.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload := map[string]string{"expiresAt": "not-a-date"}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBuffer(body))
	req.SetPathValue("userId", service.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	expired := time.Now().Add(-time.Minute).Format(time.RFC3339)
	payload = map[string]string{"expiresAt": expired}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBuffer(body))
	req.SetPathValue("userId", service.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBufferString(`{}`))
	req.SetPathValue("userId", service.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: user.ID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBufferString(`{}`))
	req.SetPathValue("userId", user.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: other.ID, Role: auth.RoleWriter}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/id/tokens", bytes.NewBufferString(`{}`))
	req.SetPathValue("userId", other.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: other.ID, Role: auth.RoleWriter}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}
}
