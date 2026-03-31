package componentanalysis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

const (
	defaultIdleBackoff        = 750 * time.Millisecond
	maxIdleBackoff            = 5 * time.Second
	defaultScheduleInterval   = 6 * time.Hour
	fallbackClaimBatchSize    = 5
	fallbackSchedulerEnqLimit = 1000
	fallbackSummaryBatchSize  = 10
	fallbackRevisionDiffBatch = 10
	minClaimBatchSize         = 1
	minSchedulerEnqueueLimit  = 1
	maxWakeSignals            = 1024
	defaultStaleLockTimeout   = 30 * time.Minute
)

type staleJobRequeuer interface {
	RequeueStaleComponentAnalysisJobs(staleAfter time.Duration, limit int) (int, error)
}

type scheduleCheckpointStore interface {
	TouchComponentAnalysisMalwareScheduleCheckpoint() (time.Time, error)
}

// Service processes component analysis queue items.
type Service struct {
	store              store.Store
	logger             *slog.Logger
	sched              atomic.Value // ScheduleConfig
	claimBatch         atomic.Int64 // int
	schedEnqLim        atomic.Int64 // int
	workerCount        atomic.Int64 // int
	wakeCh             chan struct{}
	summaryClaimBatch  atomic.Int64 // int
	summaryWorkerCount atomic.Int64 // int
	summaryWakeCh      chan struct{}
	diffClaimBatch     atomic.Int64 // int
	diffWorkerCount    atomic.Int64 // int
	diffWakeCh         chan struct{}
	scheduleAnchor     atomic.Int64 // unix nano
}

// ScheduleConfig controls when components become eligible for scheduled re-analysis.
type ScheduleConfig struct {
	Enabled  bool
	Interval time.Duration
}

// NewService constructs a component analysis service.
func NewService(st store.Store, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	svc := &Service{
		store:         st,
		logger:        logger,
		wakeCh:        make(chan struct{}, maxWakeSignals),
		summaryWakeCh: make(chan struct{}, maxWakeSignals),
		diffWakeCh:    make(chan struct{}, maxWakeSignals),
	}
	svc.sched.Store(ScheduleConfig{Enabled: true, Interval: defaultScheduleInterval})
	svc.scheduleAnchor.Store(time.Now().UTC().UnixNano())
	svc.claimBatch.Store(fallbackClaimBatchSize)
	svc.schedEnqLim.Store(fallbackSchedulerEnqLimit)
	svc.summaryClaimBatch.Store(fallbackSummaryBatchSize)
	svc.diffClaimBatch.Store(fallbackRevisionDiffBatch)
	return svc
}

// SetSchedule updates the schedule configuration for workers (used for component state TTL).
func (s *Service) SetSchedule(enabled bool, interval time.Duration) {
	if s == nil {
		return
	}
	if interval < 0 {
		interval = 0
	}
	s.sched.Store(ScheduleConfig{Enabled: enabled, Interval: interval})
}

// SetScheduleAnchor stores the last successful scheduler checkpoint timestamp.
func (s *Service) SetScheduleAnchor(ts time.Time) {
	if s == nil || ts.IsZero() {
		return
	}
	s.scheduleAnchor.Store(ts.UTC().UnixNano())
}

// ScheduleAnchor returns the last successful scheduler checkpoint timestamp.
func (s *Service) ScheduleAnchor() time.Time {
	if s == nil {
		return time.Time{}
	}
	unixNano := s.scheduleAnchor.Load()
	if unixNano <= 0 {
		return time.Time{}
	}
	return time.Unix(0, unixNano).UTC()
}

// TouchScheduleCheckpoint persists and refreshes the scheduler checkpoint timestamp.
func (s *Service) TouchScheduleCheckpoint() error {
	if s == nil {
		return nil
	}
	if checkpointStore, ok := s.store.(scheduleCheckpointStore); ok {
		ts, err := checkpointStore.TouchComponentAnalysisMalwareScheduleCheckpoint()
		if err != nil {
			return err
		}
		s.SetScheduleAnchor(ts)
		return nil
	}
	// Fallback keeps runtime behavior deterministic in tests/stubs that don't persist schedule state.
	s.SetScheduleAnchor(time.Now().UTC())
	return nil
}

// SetClaimBatchSize updates how many jobs a worker claims per poll cycle.
func (s *Service) SetClaimBatchSize(batchSize int) {
	if s == nil {
		return
	}
	if batchSize < minClaimBatchSize {
		batchSize = minClaimBatchSize
	}
	s.claimBatch.Store(int64(batchSize))
}

func (s *Service) claimBatchSize() int {
	if s == nil {
		return fallbackClaimBatchSize
	}
	value := int(s.claimBatch.Load())
	if value < minClaimBatchSize {
		return fallbackClaimBatchSize
	}
	return value
}

// ClaimBatchSize returns the current worker claim batch size.
func (s *Service) ClaimBatchSize() int {
	return s.claimBatchSize()
}

func (s *Service) summaryBatchSize() int {
	if s == nil {
		return fallbackSummaryBatchSize
	}
	value := int(s.summaryClaimBatch.Load())
	if value < 1 {
		return fallbackSummaryBatchSize
	}
	return value
}

// SetSummaryClaimBatchSize updates how many summary jobs a worker claims per poll cycle.
func (s *Service) SetSummaryClaimBatchSize(batchSize int) {
	if s == nil {
		return
	}
	if batchSize < 1 {
		batchSize = 1
	}
	s.summaryClaimBatch.Store(int64(batchSize))
}

func (s *Service) revisionDiffBatchSize() int {
	if s == nil {
		return fallbackRevisionDiffBatch
	}
	value := int(s.diffClaimBatch.Load())
	if value < 1 {
		return fallbackRevisionDiffBatch
	}
	return value
}

// SetRevisionDiffClaimBatchSize updates how many revision-diff jobs a worker claims per poll cycle.
func (s *Service) SetRevisionDiffClaimBatchSize(batchSize int) {
	if s == nil {
		return
	}
	if batchSize < 1 {
		batchSize = 1
	}
	s.diffClaimBatch.Store(int64(batchSize))
}

// SetSchedulerEnqueueLimit updates how many stale components can be enqueued per scheduler tick.
func (s *Service) SetSchedulerEnqueueLimit(limit int) {
	if s == nil {
		return
	}
	if limit < minSchedulerEnqueueLimit {
		limit = minSchedulerEnqueueLimit
	}
	s.schedEnqLim.Store(int64(limit))
}

func (s *Service) schedulerEnqueueLimit() int {
	if s == nil {
		return fallbackSchedulerEnqLimit
	}
	value := int(s.schedEnqLim.Load())
	if value < minSchedulerEnqueueLimit {
		return fallbackSchedulerEnqLimit
	}
	return value
}

// SchedulerEnqueueLimit returns the current scheduler enqueue limit.
func (s *Service) SchedulerEnqueueLimit() int {
	return s.schedulerEnqueueLimit()
}

// Schedule returns the current schedule configuration.
func (s *Service) Schedule() ScheduleConfig {
	if s == nil {
		return ScheduleConfig{}
	}
	if cfg, ok := s.sched.Load().(ScheduleConfig); ok {
		return cfg
	}
	return ScheduleConfig{}
}

// StartWorkers launches worker goroutines for component analysis.
func (s *Service) StartWorkers(ctx context.Context, workers int) {
	if s == nil || s.store == nil || workers <= 0 {
		return
	}
	// Recover stuck jobs from previous crashes/shutdowns.
	if requeuer, ok := s.store.(staleJobRequeuer); ok {
		if count, err := requeuer.RequeueStaleComponentAnalysisJobs(defaultStaleLockTimeout, 0); err != nil {
			s.logger.Warn("failed to requeue stale component analysis jobs", "error", err)
		} else if count > 0 {
			s.logger.Warn("requeued stale component analysis jobs", "count", count, "stale_after", defaultStaleLockTimeout.String())
		}
	}

	s.workerCount.Store(int64(workers))
	hostname := workerHost()
	for i := 0; i < workers; i++ {
		workerID := fmt.Sprintf("%s-component-analysis-%d", hostname, i+1)
		go s.runWorker(ctx, workerID)
	}
}

// StartSummaryWorkers launches worker goroutines for test revision malware summaries.
func (s *Service) StartSummaryWorkers(ctx context.Context, workers int) {
	if s == nil || s.store == nil || workers <= 0 {
		return
	}
	s.summaryWorkerCount.Store(int64(workers))
	hostname := workerHost()
	for i := 0; i < workers; i++ {
		workerID := fmt.Sprintf("%s-revision-summary-%d", hostname, i+1)
		go s.runSummaryWorker(ctx, workerID)
	}
}

// StartRevisionDiffWorkers launches worker goroutines for revision finding diff jobs.
func (s *Service) StartRevisionDiffWorkers(ctx context.Context, workers int) {
	if s == nil || s.store == nil || workers <= 0 {
		return
	}
	s.diffWorkerCount.Store(int64(workers))
	hostname := workerHost()
	for i := 0; i < workers; i++ {
		workerID := fmt.Sprintf("%s-revision-diff-%d", hostname, i+1)
		go s.runRevisionDiffWorker(ctx, workerID)
	}
}

// EnqueueStale schedules stale component analyses.
func (s *Service) EnqueueStale(ctx context.Context, reason string, scheduledFor *time.Time) (int, error) {
	if s == nil || s.store == nil {
		return 0, errors.New("store is nil")
	}
	_ = ctx
	count, err := s.store.EnqueueStaleComponentAnalysis(reason, scheduledFor, s.schedulerEnqueueLimit())
	if err != nil {
		return 0, err
	}
	if count > 0 {
		s.NotifyWorkers()
	}
	return count, nil
}

// NotifyWorkers wakes idle workers so they can claim newly enqueued jobs immediately.
// This is best-effort. Signals are buffered so that a wakeup is not lost if a worker
// transitions to idle slightly after the notification.
func (s *Service) NotifyWorkers() {
	if s == nil {
		return
	}
	notify := func(ch chan struct{}, n int) {
		if n < 1 {
			return
		}
		if n > maxWakeSignals {
			n = maxWakeSignals
		}
		for i := 0; i < n; i++ {
			select {
			case ch <- struct{}{}:
			default:
				return
			}
		}
	}

	notify(s.wakeCh, int(s.workerCount.Load()))
	notify(s.summaryWakeCh, int(s.summaryWorkerCount.Load()))
	notify(s.diffWakeCh, int(s.diffWorkerCount.Load()))
}

func (s *Service) runWorker(ctx context.Context, workerID string) {
	logger := s.logger.With("component", "component_analysis.worker", "worker_id", workerID)
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
			ok, reason := s.waitForWake(ctx)
			if !ok {
				return
			}
			logger.Debug("worker wakeup", "reason", reason)
			isIdle = false
			wokeFromIdle = true
		}

		jobs, err := s.store.ClaimComponentAnalysisJobs(s.claimBatchSize(), workerID)
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
			if err := s.processJob(ctx, job.ComponentPURL); err != nil {
				logger.Error("job failed", "queue_id", job.ID, "component_purl", job.ComponentPURL, "error", err)
				_ = s.store.UpdateComponentAnalysisQueueStatus(job.ID, store.ComponentAnalysisStatusFailed, err.Error())
				continue
			}
			if err := s.store.UpdateComponentAnalysisQueueStatus(job.ID, store.ComponentAnalysisStatusCompleted, ""); err != nil {
				logger.Error("failed to finalize job", "queue_id", job.ID, "error", err)
			} else {
				logger.Debug("job completed", "queue_id", job.ID, "component_purl", job.ComponentPURL)
			}
		}
	}
}

func (s *Service) processJob(ctx context.Context, componentPURL string) error {
	if s == nil || s.store == nil {
		return errors.New("store is nil")
	}
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return errors.New("component purl empty")
	}

	now := time.Now().UTC()
	if matcher, ok := s.store.(malwareMatchCandidateLister); ok {
		candidates, err := matcher.ListMalwareMatchCandidates(componentPURL)
		if err != nil {
			return err
		}
		inputByMalware := make(map[string]store.ComponentAnalysisFindingInput, len(candidates))
		for _, candidate := range candidates {
			matched, matchType, malwarePURL := matchSmart(componentPURL, candidate)
			if !matched {
				continue
			}
			malwarePURL = strings.TrimSpace(malwarePURL)
			if malwarePURL == "" || candidate.SourceMalwareInputResultID == uuid.Nil {
				continue
			}
			next := store.ComponentAnalysisFindingInput{
				ComponentPURL:              componentPURL,
				MalwarePURL:                malwarePURL,
				SourceMalwareInputResultID: candidate.SourceMalwareInputResultID,
				MatchType:                  matchType,
			}
			if prev, ok := inputByMalware[malwarePURL]; !ok || matchPriority(next.MatchType) > matchPriority(prev.MatchType) {
				inputByMalware[malwarePURL] = next
			}
		}

		malwarePURLs := make([]string, 0, len(inputByMalware))
		for malwarePURL := range inputByMalware {
			malwarePURLs = append(malwarePURLs, malwarePURL)
		}
		sort.Strings(malwarePURLs)
		for _, malwarePURL := range malwarePURLs {
			input := inputByMalware[malwarePURL]
			if _, err := s.store.UpsertComponentAnalysisFinding(input); err != nil {
				return err
			}
		}
	} else {
		// Compatibility fallback for non-Postgres/in-memory stubs that don't expose raw candidates.
		results, err := s.store.ListAnalysisResultsForComponentMatch(componentPURL)
		if err != nil {
			return err
		}
		for _, result := range results {
			matchType := store.ComponentAnalysisMatchContainsPrefix
			if strings.EqualFold(result.ComponentPURL, componentPURL) {
				matchType = store.ComponentAnalysisMatchExact
			}
			_, err := s.store.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
				ComponentPURL:              componentPURL,
				MalwarePURL:                result.ComponentPURL,
				SourceMalwareInputResultID: result.ID,
				MatchType:                  matchType,
			})
			if err != nil {
				return err
			}
		}
	}

	cfg := s.Schedule()
	var validUntil *time.Time
	if cfg.Enabled && cfg.Interval > 0 {
		value := now.Add(cfg.Interval)
		validUntil = &value
	}
	if _, err := s.store.UpsertComponentAnalysisMalwareComponentState(componentPURL, now, validUntil); err != nil {
		return err
	}

	// Component analysis results changed. Enqueue recomputation for active revisions containing this component.
	if count, err := s.store.EnqueueActiveTestRevisionMalwareSummaryByComponentPURL(
		componentPURL,
		store.TestRevisionMalwareSummaryReasonComponentAnalysisUpdate,
	); err != nil {
		return err
	} else if count > 0 {
		s.NotifyWorkers()
	}

	_ = ctx
	return nil
}

func (s *Service) waitForWake(ctx context.Context) (bool, string) {
	select {
	case <-ctx.Done():
		return false, "ctx_done"
	case <-s.wakeCh:
		return true, "signal"
	}
}

func growBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return defaultIdleBackoff
	}
	next := current * 2
	if next > maxIdleBackoff {
		return maxIdleBackoff
	}
	return next
}

func workerHost() string {
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return host
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "worker"
	}
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() && ip.IP.To4() != nil {
			return ip.IP.String()
		}
	}
	return "worker"
}
