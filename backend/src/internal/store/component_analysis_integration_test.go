package store_test

import (
	"time"

	"testing"

	"backend/internal/store"
	"backend/internal/tests"
)

func TestComponentAnalysisQueueDedupAndHistory(t *testing.T) {
	storeInstance, _ := tests.NewPostgresTestStore(t)

	first, err := storeInstance.EnqueueComponentAnalysis("pkg:npm/leftpad@1.0.0", store.ComponentAnalysisReasonManual, nil)
	if err != nil {
		t.Fatalf("enqueue first: %v", err)
	}
	second, err := storeInstance.EnqueueComponentAnalysis("pkg:npm/leftpad@1.0.0", store.ComponentAnalysisReasonManual, nil)
	if err != nil {
		t.Fatalf("enqueue second: %v", err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected same active queue id")
	}

	if err := storeInstance.UpdateComponentAnalysisQueueStatus(first.ID, store.ComponentAnalysisStatusProcessing, ""); err != nil {
		t.Fatalf("mark processing: %v", err)
	}
	if err := storeInstance.UpdateComponentAnalysisQueueStatus(first.ID, store.ComponentAnalysisStatusCompleted, ""); err != nil {
		t.Fatalf("complete queue: %v", err)
	}

	third, err := storeInstance.EnqueueComponentAnalysis("pkg:npm/leftpad@1.0.0", store.ComponentAnalysisReasonManual, nil)
	if err != nil {
		t.Fatalf("enqueue third: %v", err)
	}
	if third.ID == first.ID {
		t.Fatalf("expected new queue id after completion")
	}

	items, err := storeInstance.ListComponentAnalysisQueue(store.ComponentAnalysisQueueFilter{
		ComponentPURL: "pkg:npm/leftpad@1.0.0",
		Limit:         10,
		Offset:        0,
	})
	if err != nil {
		t.Fatalf("list queue: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 queue items, got %d", len(items))
	}
}

func TestComponentAnalysisQueueRequeueStaleProcessingJobs(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	item, err := storeInstance.EnqueueComponentAnalysis("pkg:npm/stalejob@1.0.0", store.ComponentAnalysisReasonManual, nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Mark as PROCESSING and simulate an old lock (abrupt shutdown scenario).
	if err := storeInstance.UpdateComponentAnalysisQueueStatus(item.ID, store.ComponentAnalysisStatusProcessing, ""); err != nil {
		t.Fatalf("mark processing: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE component_analysis_malware_queue
		 SET locked_at = NOW() - interval '2 hours',
		     locked_by = 'test-worker',
		     updated_at = NOW()
		 WHERE id = $1`,
		item.ID,
	); err != nil {
		t.Fatalf("set stale lock: %v", err)
	}

	requeued, err := storeInstance.RequeueStaleComponentAnalysisJobs(30*time.Minute, 0)
	if err != nil {
		t.Fatalf("requeue stale: %v", err)
	}
	if requeued != 1 {
		t.Fatalf("expected 1 requeued job, got %d", requeued)
	}

	got, err := storeInstance.GetComponentAnalysisQueueItem(item.ID)
	if err != nil {
		t.Fatalf("get queue item: %v", err)
	}
	if got.Status != store.ComponentAnalysisStatusPending {
		t.Fatalf("expected status PENDING after requeue, got %s", got.Status)
	}
	if got.LockedAt != nil || got.LockedBy != "" {
		t.Fatalf("expected lock cleared after requeue, got lockedAt=%v lockedBy=%q", got.LockedAt, got.LockedBy)
	}

	// Non-stale lock should not be requeued.
	if err := storeInstance.UpdateComponentAnalysisQueueStatus(item.ID, store.ComponentAnalysisStatusProcessing, ""); err != nil {
		t.Fatalf("mark processing again: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE component_analysis_malware_queue
		 SET locked_at = NOW(),
		     locked_by = 'test-worker',
		     updated_at = NOW()
		 WHERE id = $1`,
		item.ID,
	); err != nil {
		t.Fatalf("set fresh lock: %v", err)
	}
	requeued, err = storeInstance.RequeueStaleComponentAnalysisJobs(30*time.Minute, 0)
	if err != nil {
		t.Fatalf("requeue fresh: %v", err)
	}
	if requeued != 0 {
		t.Fatalf("expected 0 requeued jobs for fresh lock, got %d", requeued)
	}
}
