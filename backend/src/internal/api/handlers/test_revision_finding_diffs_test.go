package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListTestRevisionLastChangesHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("ReimportChanges-Product", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "ReimportChanges-Scope", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "ReimportChanges-Test", "cyclonedx", "1.6")

	now := time.Now().UTC()
	toRevisionID := uuid.New()
	wrapped := tests.StoreWrapper{
		Store: pgStore,
		ListTestRevisionLastChangesItems: []models.TestRevisionChangeSummary{
			{
				ToRevisionID:    toRevisionID,
				ProjectID:       product.ProjectID,
				TestID:          testItem.ID,
				AddedCount:      1,
				RemovedCount:    2,
				UnchangedCount:  3,
				ReappearedCount: 4,
				Status:          store.TestRevisionFindingDiffStatusCompleted,
				CreatedAt:       now,
				UpdatedAt:       now,
			},
		},
	}
	handler := ListTestRevisionLastChangesHandler(wrapped)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions/last-changes", nil)
	req.SetPathValue("testId", testItem.ID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestListTestRevisionChangesHandler_InvalidDiffType(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("ReimportDiff-Product", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "ReimportDiff-Scope", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "ReimportDiff-Test", "cyclonedx", "1.6")

	handler := ListTestRevisionChangesHandler(tests.StoreWrapper{Store: pgStore})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions/r1/changes?diffType=not-a-type", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("revisionId", uuid.New().String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}
}

func TestGetTestRevisionChangesSummaryHandler_NotFound(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("ReimportSummary-Product", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "ReimportSummary-Scope", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "ReimportSummary-Test", "cyclonedx", "1.6")

	wrapped := tests.StoreWrapper{
		Store:                           pgStore,
		GetTestRevisionChangeSummaryErr: store.ErrNotFound,
	}
	handler := GetTestRevisionChangesSummaryHandler(wrapped)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/id/revisions/r1/changes/summary", nil)
	req.SetPathValue("testId", testItem.ID.String())
	req.SetPathValue("revisionId", uuid.New().String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}
