package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListComponentsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	handler := ListComponentsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/bad/components", nil)
	req.SetPathValue("testId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components?page=0", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListComponentsPageErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	ListComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	wrapped = tests.StoreWrapper{Store: pgStore, ListComponentsPageErr: store.ErrNotFound}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	ListComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	component := models.Component{
		ID:         uuid.New(),
		RevisionID: uuid.New(),
		PURL:       "pkg:pypi/demo@1.0.0",
		PkgName:    "demo",
		Version:    "1.0.0",
		PkgType:    "library",
		CreatedAt:  time.Now().UTC(),
	}
	wrapped = tests.StoreWrapper{Store: pgStore, ListComponentsPageItems: []models.Component{component}}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	ListComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestCountComponentsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	handler := CountComponentsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/bad/components/count", nil)
	req.SetPathValue("testId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, CountComponentsErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/count", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	CountComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	wrapped = tests.StoreWrapper{Store: pgStore, CountComponentsErr: store.ErrNotFound}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/count", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	CountComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	value := 123
	wrapped = tests.StoreWrapper{Store: pgStore, CountComponentsValue: &value}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/count", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	CountComponentsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestGetComponentHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	handler := GetComponentHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/bad/components/id", nil)
	req.SetPathValue("testId", "bad")
	req.SetPathValue("componentId", uuid.New().String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/bad", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("componentId", "bad")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, GetComponentErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/id", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("componentId", uuid.New().String())
	recorder = httptest.NewRecorder()
	GetComponentHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	wrapped = tests.StoreWrapper{Store: pgStore, GetComponentMissing: true}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/id", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("componentId", uuid.New().String())
	recorder = httptest.NewRecorder()
	GetComponentHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	component := &models.Component{
		ID:         uuid.New(),
		RevisionID: uuid.New(),
		PURL:       "pkg:pypi/demo@1.0.0",
		PkgName:    "demo",
		Version:    "1.0.0",
		PkgType:    "library",
		CreatedAt:  time.Now().UTC(),
	}
	wrapped = tests.StoreWrapper{Store: pgStore, GetComponentItem: component}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/components/id", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("componentId", uuid.New().String())
	recorder = httptest.NewRecorder()
	GetComponentHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}
