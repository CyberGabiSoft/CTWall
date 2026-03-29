package componentanalysis

import (
	"context"
	"errors"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

func (s *Service) runSummaryWorker(ctx context.Context, workerID string) {
	if s == nil {
		return
	}
	logger := s.logger.With("component", "component_analysis.summary_worker", "worker_id", workerID)
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
			ok, reason := s.waitForSummaryWake(ctx)
			if !ok {
				return
			}
			logger.Debug("worker wakeup", "reason", reason)
			isIdle = false
			wokeFromIdle = true
		}

		jobs, err := s.store.ClaimTestRevisionMalwareSummaryJobs(s.summaryBatchSize(), workerID)
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
			if err := s.processSummaryJob(ctx, job.RevisionID); err != nil {
				logger.Error("job failed", "queue_id", job.ID, "revision_id", job.RevisionID, "error", err)
				_ = s.store.UpdateTestRevisionMalwareSummaryQueueStatus(job.ID, store.TestRevisionMalwareSummaryStatusFailed, err.Error())
				continue
			}
			if err := s.store.UpdateTestRevisionMalwareSummaryQueueStatus(job.ID, store.TestRevisionMalwareSummaryStatusCompleted, ""); err != nil {
				logger.Error("failed to finalize job", "queue_id", job.ID, "error", err)
			} else {
				logger.Debug("job completed", "queue_id", job.ID, "revision_id", job.RevisionID)
			}
		}
	}
}

func (s *Service) processSummaryJob(ctx context.Context, revisionID uuid.UUID) error {
	if s == nil || s.store == nil {
		return errors.New("store is nil")
	}
	if revisionID == uuid.Nil {
		return errors.New("revision id is empty")
	}

	_, err := s.store.ComputeAndStoreTestRevisionMalwareSummary(revisionID)
	if err != nil {
		return err
	}
	_ = ctx
	return nil
}

func (s *Service) waitForSummaryWake(ctx context.Context) (bool, string) {
	select {
	case <-ctx.Done():
		return false, "ctx_done"
	case <-s.summaryWakeCh:
		return true, "signal"
	}
}
