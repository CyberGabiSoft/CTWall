package componentanalysis

import (
	"context"
	"log/slog"
	"time"

	"backend/internal/store"
)

// Scheduler runs periodic EnqueueStale() based on the configured interval.
// It can be updated at runtime (e.g. via API).
type Scheduler struct {
	svc      *Service
	logger   *slog.Logger
	updateCh chan struct{}
}

// NewScheduler constructs a scheduler instance.
func NewScheduler(svc *Service, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		svc:      svc,
		logger:   logger.With("component", "component_analysis.scheduler"),
		updateCh: make(chan struct{}, 1),
	}
}

// Start launches the scheduler loop.
func (s *Scheduler) Start(ctx context.Context) {
	if s == nil || s.svc == nil {
		return
	}
	go s.loop(ctx)
}

// Notify wakes the scheduler loop (used after config updates).
func (s *Scheduler) Notify() {
	if s == nil {
		return
	}
	select {
	case s.updateCh <- struct{}{}:
	default:
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	s.logger.Info("scheduler started")
	defer s.logger.Info("scheduler stopped")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cfg := s.svc.Schedule()
		if !cfg.Enabled || cfg.Interval <= 0 {
			select {
			case <-ctx.Done():
				return
			case <-s.updateCh:
				continue
			}
		}
		timer := time.NewTimer(s.timeUntilNextRun(cfg.Interval))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.updateCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		case <-timer.C:
			timer.Stop()
		}

		s.runEnqueuePass(ctx)
	}
}

func (s *Scheduler) timeUntilNextRun(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	anchor := s.svc.ScheduleAnchor()
	if anchor.IsZero() {
		return interval
	}
	nextRunAt := anchor.Add(interval)
	wait := time.Until(nextRunAt)
	if wait < 0 {
		return 0
	}
	return wait
}

func (s *Scheduler) runEnqueuePass(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		limit := s.svc.SchedulerEnqueueLimit()
		count, err := s.svc.EnqueueStale(ctx, store.ComponentAnalysisReasonScheduled, nil)
		if err != nil {
			s.logger.Error("scheduled enqueue failed", "error", err)
			return
		}
		if count >= limit {
			// Keep draining stale backlog in the same pass when there are still non-queued candidates.
			s.logger.Warn("scheduled enqueue hit limit (continuing catch-up)", "count", count, "limit", limit)
			continue
		}
		if err := s.svc.TouchScheduleCheckpoint(); err != nil {
			s.logger.Error("failed to persist scheduler checkpoint", "error", err)
		}
		s.logger.Info("scheduled enqueue completed", "count", count, "limit", limit)
		return
	}
}
