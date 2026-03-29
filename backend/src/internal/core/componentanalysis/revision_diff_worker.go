package componentanalysis

import (
	"context"
	"errors"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

func (s *Service) runRevisionDiffWorker(ctx context.Context, workerID string) {
	if s == nil {
		return
	}
	logger := s.logger.With("component", "component_analysis.revision_diff_worker", "worker_id", workerID)
	if s.store == nil {
		logger.Error("store is nil")
		return
	}
	logger.Info("worker started")
	defer logger.Info("worker stopped")

	isIdle := false
	claimBackoff := defaultIdleBackoff
	wokeFromIdle := false
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if isIdle {
			ok, reason := s.waitForRevisionDiffWake(ctx)
			if !ok {
				return
			}
			logger.Debug("worker wakeup", "reason", reason)
			isIdle = false
			wokeFromIdle = true
		}

		jobs, err := s.store.ClaimTestRevisionFindingDiffJobs(s.revisionDiffBatchSize(), workerID)
		if err != nil {
			logger.Error("failed to claim jobs", "error", err)
			time.Sleep(claimBackoff)
			claimBackoff = growBackoff(claimBackoff)
			continue
		}
		if len(jobs) == 0 {
			if !isIdle {
				isIdle = true
				logger.Debug("worker idle", "reason", "no_jobs")
			}
			continue
		}
		claimBackoff = defaultIdleBackoff
		if wokeFromIdle {
			logger.Debug("worker active")
			wokeFromIdle = false
		}

		for _, job := range jobs {
			if err := s.processRevisionDiffJob(ctx, job.ToRevisionID); err != nil {
				logger.Error("job failed", "queue_id", job.ID, "to_revision_id", job.ToRevisionID, "error", err)
				_ = s.store.UpdateTestRevisionFindingDiffQueueStatus(job.ID, store.TestRevisionFindingDiffStatusFailed, err.Error())
				continue
			}
			if err := s.store.UpdateTestRevisionFindingDiffQueueStatus(job.ID, store.TestRevisionFindingDiffStatusCompleted, ""); err != nil {
				logger.Error("failed to finalize job", "queue_id", job.ID, "error", err)
			} else {
				logger.Debug("job completed", "queue_id", job.ID, "to_revision_id", job.ToRevisionID)
			}
		}
	}
}

func (s *Service) processRevisionDiffJob(ctx context.Context, toRevisionID uuid.UUID) error {
	if s == nil || s.store == nil {
		return errors.New("store is nil")
	}
	if toRevisionID == uuid.Nil {
		return errors.New("revision id is empty")
	}
	_, err := s.store.ComputeAndStoreTestRevisionFindingDiff(toRevisionID)
	if err != nil {
		return err
	}
	_ = ctx
	return nil
}

func (s *Service) waitForRevisionDiffWake(ctx context.Context) (bool, string) {
	select {
	case <-ctx.Done():
		return false, "ctx_done"
	case <-s.diffWakeCh:
		return true, "signal"
	}
}
