package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListTestsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	_, _, _ = pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")

	handler := ListTestsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scopes/bad/tests", nil)
	req.SetPathValue("scopeId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes/id/tests?page=0", nil)
	req.SetPathValue("scopeId", scope.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes/missing/tests", nil)
	req.SetPathValue("scopeId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListTestsErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes/id/tests", nil)
	req.SetPathValue("scopeId", scope.ID.String())
	recorder = httptest.NewRecorder()
	ListTestsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/scopes/id/tests", nil)
	req.SetPathValue("scopeId", scope.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestListAllTestsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := ListAllTestsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests?page=0", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListAllTestsErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests", nil)
	recorder = httptest.NewRecorder()
	ListAllTestsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestListRevisionsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	if _, err := pgStore.StoreSbom("sha1", []byte("data"), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	_, _ = pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha1"})

	handler := ListRevisionsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/bad/revisions", nil)
	req.SetPathValue("testId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions?page=0", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/missing/revisions", nil)
	req.SetPathValue("testId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, ListRevisionsErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	ListRevisionsHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestDeleteTestHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	handler := DeleteTestHandler(pgStore)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tests/bad", nil)
	req.SetPathValue("testId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/tests/missing", nil)
	req.SetPathValue("testId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, DeleteTestErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/tests/id", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	DeleteTestHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/tests/id", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}
