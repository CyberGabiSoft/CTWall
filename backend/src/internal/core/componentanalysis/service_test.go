package componentanalysis

import (
	"context"
	"testing"
	"time"
)

func TestScheduleConfig(t *testing.T) {
	svc := NewService(nil, nil)
	cfg := svc.Schedule()
	if !cfg.Enabled {
		t.Fatalf("expected default schedule enabled")
	}
	if cfg.Interval != 6*time.Hour {
		t.Fatalf("expected default interval 6h, got %s", cfg.Interval)
	}

	svc.SetSchedule(false, 0)
	cfg = svc.Schedule()
	if cfg.Enabled {
		t.Fatalf("expected schedule disabled")
	}
	if cfg.Interval != 0 {
		t.Fatalf("expected interval 0, got %s", cfg.Interval)
	}

	svc.SetSchedule(true, -1)
	cfg = svc.Schedule()
	if !cfg.Enabled {
		t.Fatalf("expected schedule enabled")
	}
	if cfg.Interval != 0 {
		t.Fatalf("expected negative interval to clamp to 0, got %s", cfg.Interval)
	}
}

func TestBatchSizeAndLimitClamps(t *testing.T) {
	svc := NewService(nil, nil)

	svc.SetClaimBatchSize(0)
	if got := svc.ClaimBatchSize(); got != 1 {
		t.Fatalf("expected claim batch to clamp to 1, got %d", got)
	}

	svc.SetSummaryClaimBatchSize(0)
	if got := svc.summaryBatchSize(); got != 1 {
		t.Fatalf("expected summary claim batch to clamp to 1, got %d", got)
	}

	svc.SetRevisionDiffClaimBatchSize(0)
	if got := svc.revisionDiffBatchSize(); got != 1 {
		t.Fatalf("expected revision diff claim batch to clamp to 1, got %d", got)
	}

	svc.SetSchedulerEnqueueLimit(0)
	if got := svc.SchedulerEnqueueLimit(); got != 1 {
		t.Fatalf("expected scheduler enqueue limit to clamp to 1, got %d", got)
	}
}

func TestNotifyWorkersSignals(t *testing.T) {
	svc := NewService(nil, nil)
	svc.workerCount.Store(3)
	svc.summaryWorkerCount.Store(2)
	svc.diffWorkerCount.Store(1)

	svc.NotifyWorkers()

	if got := len(svc.wakeCh); got != 3 {
		t.Fatalf("expected 3 wake signals, got %d", got)
	}
	if got := len(svc.summaryWakeCh); got != 2 {
		t.Fatalf("expected 2 summary wake signals, got %d", got)
	}
	if got := len(svc.diffWakeCh); got != 1 {
		t.Fatalf("expected 1 diff wake signal, got %d", got)
	}
}

func TestWaitForWakeAndContextCancel(t *testing.T) {
	svc := NewService(nil, nil)
	svc.wakeCh <- struct{}{}
	if ok, reason := svc.waitForWake(context.Background()); !ok || reason != "signal" {
		t.Fatalf("expected wake signal, got ok=%v reason=%s", ok, reason)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, reason := svc.waitForWake(ctx); ok || reason != "ctx_done" {
		t.Fatalf("expected ctx_done, got ok=%v reason=%s", ok, reason)
	}
}

func TestGrowBackoff(t *testing.T) {
	if got := growBackoff(0); got != defaultIdleBackoff {
		t.Fatalf("expected default idle backoff, got %s", got)
	}
	if got := growBackoff(defaultIdleBackoff); got != 2*defaultIdleBackoff {
		t.Fatalf("expected doubled backoff, got %s", got)
	}
	if got := growBackoff(maxIdleBackoff); got != maxIdleBackoff {
		t.Fatalf("expected capped backoff, got %s", got)
	}
}

func TestScheduleAnchorAndCheckpointFallback(t *testing.T) {
	svc := NewService(nil, nil)
	if got := svc.ScheduleAnchor(); got.IsZero() {
		t.Fatalf("expected non-zero initial schedule anchor")
	}

	prev := svc.ScheduleAnchor()
	svc.SetScheduleAnchor(time.Time{})
	if got := svc.ScheduleAnchor(); got.IsZero() {
		t.Fatalf("expected zero timestamp input to be ignored")
	}

	// Fallback path when store does not implement scheduleCheckpointStore.
	if err := svc.TouchScheduleCheckpoint(); err != nil {
		t.Fatalf("touch schedule checkpoint fallback failed: %v", err)
	}
	if got := svc.ScheduleAnchor(); got.Before(prev) {
		t.Fatalf("expected checkpoint anchor not to move backwards")
	}
}

func TestWorkerHostNotEmpty(t *testing.T) {
	if got := workerHost(); got == "" {
		t.Fatalf("expected non-empty worker host")
	}
}
