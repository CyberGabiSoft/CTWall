package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListScopesHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	_, _ = pgStore.CreateScope(product.ID, "Payments", "")
	handler := ListScopesHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/bad/scopes", nil)
	req.SetPathValue("productId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/id/scopes?page=0", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/missing/scopes", nil)
	req.SetPathValue("productId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListScopesErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/id/scopes", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	ListScopesHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/id/scopes", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestListAllScopesHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := ListAllScopesHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scopes?page=0", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListAllScopesErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes", nil)
	recorder = httptest.NewRecorder()
	ListAllScopesHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestCreateScopeHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	handler := CreateScopeHandler(pgStore)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/products/bad/scopes", nil)
	req.SetPathValue("productId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewBufferString("bad"))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload := map[string]string{"name": " "}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"name": strings.Repeat("a", maxNameLength+1)}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"name": "Payments"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/missing/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, CreateScopeErr: errors.New("boom")}
	payload = map[string]string{"name": "Core"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products/id/scopes", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	CreateScopeHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestDeleteScopeHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	handler := DeleteScopeHandler(pgStore)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/scopes/bad", nil)
	req.SetPathValue("scopeId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/scopes/missing", nil)
	req.SetPathValue("scopeId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, DeleteScopeErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/scopes/id", nil)
	req.SetPathValue("scopeId", scope.ID.String())
	recorder = httptest.NewRecorder()
	DeleteScopeHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/scopes/id", nil)
	req.SetPathValue("scopeId", scope.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}
