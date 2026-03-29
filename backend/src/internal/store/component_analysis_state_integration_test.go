package store_test

import (
	"testing"
	"time"

	"backend/internal/store"
	"backend/internal/tests"
)

func TestComponentAnalysisBatchRespectsComponentState(t *testing.T) {
	storeInstance, _ := tests.NewPostgresTestStore(t)

	purl := "pkg:npm/leftpad@1.0.0"
	count, err := storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonBackfill, nil)
	if err != nil {
		t.Fatalf("enqueue batch: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 queued item, got %d", count)
	}

	if _, err := storeInstance.UpsertComponentAnalysisMalwareComponentState(purl, time.Now().UTC(), nil); err != nil {
		t.Fatalf("upsert state: %v", err)
	}

	count, err = storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonBackfill, nil)
	if err != nil {
		t.Fatalf("enqueue batch again: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 queued items after fresh state, got %d", count)
	}
}
