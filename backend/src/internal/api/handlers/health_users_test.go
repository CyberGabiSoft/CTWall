package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/buildinfo"
	"backend/internal/core/auth"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	HealthHandler(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload)
	}
	if payload["version"] != buildinfo.Version {
		t.Fatalf("unexpected version: got %q, want %q", payload["version"], buildinfo.Version)
	}
}

func TestListUsersHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users?page=0", nil)
	recorder := httptest.NewRecorder()
	ListUsersHandler(pgStore).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	recorder = httptest.NewRecorder()
	ListUsersHandler(pgStore).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if recorder.Body.String() != "[]\n" {
		t.Fatalf("expected empty list, got %q", recorder.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	recorder = httptest.NewRecorder()
	ListUsersHandler(tests.StoreWrapper{Store: pgStore, ListUsersErr: errors.New("boom")}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestDeleteUserHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := DeleteUserHandler(pgStore)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/bad", nil)
	req.SetPathValue("userId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/missing", nil)
	req.SetPathValue("userId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/id", nil)
	req.SetPathValue("userId", uuid.New().String())
	recorder = httptest.NewRecorder()
	DeleteUserHandler(tests.StoreWrapper{Store: pgStore, DeleteUserErr: errors.New("boom")}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	hash, err := auth.HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := pgStore.CreateUser("delete@example.com", hash, "ADMIN", "USER", "User")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/users/id", nil)
	req.SetPathValue("userId", user.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}
