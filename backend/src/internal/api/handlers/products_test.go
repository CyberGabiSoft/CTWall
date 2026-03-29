package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListProductsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	_, _ = pgStore.CreateProduct("Alpha", "")

	handler := ListProductsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products?page=0", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListProductsErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	recorder = httptest.NewRecorder()
	ListProductsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestCreateProductHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := CreateProductHandler(pgStore)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewBufferString("bad"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload := map[string]string{"name": " "}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"name": strings.Repeat("a", maxNameLength+1)}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	payload = map[string]string{"name": "Alpha"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, CreateProductWithOwnerErr: errors.New("boom")}
	payload = map[string]string{"name": "Beta"}
	body, _ = json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	CreateProductHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestCreateProductHandlerRejectsNonOwnerGroup(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := CreateProductHandler(pgStore)

	owner, err := pgStore.CreateUser(
		fmt.Sprintf("owner-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Owner",
	)
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	actor, err := pgStore.CreateUser(
		fmt.Sprintf("actor-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Actor",
	)
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	projects, err := pgStore.ListProjectsForUser(owner.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	group, err := pgStore.CreateGroupInProject(projects[0].ID, "Owners Team", "", owner.ID)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	payload := map[string]string{
		"name":         "Alpha",
		"ownerGroupId": group.ID.String(),
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(body))
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
		ID:          actor.ID,
		Email:       actor.Email,
		Role:        auth.RoleAdmin,
		AccountType: auth.AccountTypeUser,
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestGetProductHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	handler := GetProductHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/bad", nil)
	req.SetPathValue("productId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/missing", nil)
	req.SetPathValue("productId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, GetProductErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/id", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	GetProductHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/id", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestDeleteProductHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	handler := DeleteProductHandler(pgStore)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/products/bad", nil)
	req.SetPathValue("productId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/products/missing", nil)
	req.SetPathValue("productId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, DeleteProductErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/products/id", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	DeleteProductHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/products/id", nil)
	req.SetPathValue("productId", product.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}
