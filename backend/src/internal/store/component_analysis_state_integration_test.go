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
	count, err := storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonScheduled, nil)
	if err != nil {
		t.Fatalf("enqueue batch: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 queued item, got %d", count)
	}

	if _, err := storeInstance.UpsertComponentAnalysisMalwareComponentState(purl, time.Now().UTC(), nil); err != nil {
		t.Fatalf("upsert state: %v", err)
	}

	count, err = storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonScheduled, nil)
	if err != nil {
		t.Fatalf("enqueue batch again: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 queued items after fresh state, got %d", count)
	}
}

func TestComponentAnalysisBatchBackfillIgnoresFreshState(t *testing.T) {
	storeInstance, _ := tests.NewPostgresTestStore(t)

	purl := "pkg:npm/leftpad@2.0.0"
	count, err := storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonBackfill, nil)
	if err != nil {
		t.Fatalf("enqueue backfill batch: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 queued item, got %d", count)
	}

	items, err := storeInstance.ListComponentAnalysisQueue(store.ComponentAnalysisQueueFilter{
		ComponentPURL: purl,
		Limit:         10,
		Offset:        0,
	})
	if err != nil {
		t.Fatalf("list queue: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 queue item, got %d", len(items))
	}
	if err := storeInstance.UpdateComponentAnalysisQueueStatus(items[0].ID, store.ComponentAnalysisStatusProcessing, ""); err != nil {
		t.Fatalf("mark queue item processing: %v", err)
	}
	if err := storeInstance.UpdateComponentAnalysisQueueStatus(items[0].ID, store.ComponentAnalysisStatusCompleted, ""); err != nil {
		t.Fatalf("complete queue item: %v", err)
	}

	if _, err := storeInstance.UpsertComponentAnalysisMalwareComponentState(purl, time.Now().UTC(), nil); err != nil {
		t.Fatalf("upsert fresh state: %v", err)
	}

	count, err = storeInstance.EnqueueComponentAnalysisBatch([]string{purl}, store.ComponentAnalysisReasonBackfill, nil)
	if err != nil {
		t.Fatalf("enqueue backfill batch again: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 queued item after reimport/backfill, got %d", count)
	}
}
