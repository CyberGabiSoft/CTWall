package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestSearchComponentOccurrencesHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := SearchComponentOccurrencesHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search/component-occurrences?page=0&q=pkg:npm/a", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search/component-occurrences?page=1&pageSize=10", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, SearchComponentOccurrencesErr: errors.New("boom")}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/search/component-occurrences?page=1&pageSize=10&q=pkg:npm/a", nil)
	recorder = httptest.NewRecorder()
	SearchComponentOccurrencesHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	now := time.Now().UTC()
	wrapped = tests.StoreWrapper{
		Store: pgStore,
		SearchComponentOccurrencesItems: []store.ComponentOccurrence{
			{
				ComponentID:    uuid.New(),
				RevisionID:     uuid.New(),
				PURL:           "pkg:npm/demo@1.0.0",
				PkgName:        "demo",
				Version:        "1.0.0",
				PkgType:        "library",
				PkgNamespace:   "",
				CreatedAt:      now,
				TestID:         uuid.New(),
				TestName:       "Test A",
				ScopeID:        uuid.New(),
				ScopeName:      "Scope A",
				ProductID:      uuid.New(),
				ProductName:    "Product A",
				MalwareVerdict: "UNKNOWN",
			},
		},
		SearchComponentOccurrencesTotal: 1,
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/search/component-occurrences?page=1&pageSize=10&q=pkg:npm/demo", nil)
	recorder = httptest.NewRecorder()
	SearchComponentOccurrencesHandler(wrapped).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}
