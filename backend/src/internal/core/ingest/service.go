package ingest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"backend/internal/models"
	"backend/internal/store"

	"backend/internal/sbom"
	"github.com/google/uuid"
)

const (
	// OpUpdateStage indicates a failure updating ingest stage.
	OpUpdateStage = "update_stage"
	// OpUpdateStatus indicates a failure updating ingest status.
	OpUpdateStatus = "update_status"
	// OpStoreSbom indicates a failure storing the SBOM payload.
	OpStoreSbom = "store_sbom"
	// OpAddRevision indicates a failure creating a revision.
	OpAddRevision = "add_revision"
	// OpEnqueueAnalysis indicates a failure enqueuing component analysis.
	OpEnqueueAnalysis = "enqueue_analysis"
)

// ProcessInput defines the payload needed to process an ingest job.
type ProcessInput struct {
	JobID            uuid.UUID
	TestID           uuid.UUID
	SbomSha256       string
	SbomStandard     string
	SbomSpecVersion  string
	SbomProducer     string
	SbomFormat       string
	Tags             []string
	MetadataJSON     json.RawMessage
	SbomMetadataJSON json.RawMessage
	ContentType      string
	IsGzip           bool
	ComponentsCount  int
	Components       []store.ComponentInput
	Payload          []byte
}

// ProcessResult contains the outcome of processing an ingest job.
type ProcessResult struct {
	Revision *models.TestRevision
}

// ProcessError wraps errors produced during ingest processing.
type ProcessError struct {
	Op  string
	Err error
}

func (e *ProcessError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return e.Op
	}
	return e.Op + ": " + e.Err.Error()
}

func (e *ProcessError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Processor handles ingest queue processing steps after validation/resolution.
type Processor struct {
	store          store.Store
	logger         *slog.Logger
	enqueueWorkers int
	notifier       componentAnalysisNotifier
}

type componentAnalysisNotifier interface {
	NotifyWorkers()
}

// ProcessorConfig defines optional configuration for the processor.
type ProcessorConfig struct {
	EnqueueWorkers int
	Notifier       componentAnalysisNotifier
}

// NewProcessor builds a processor that will log via the provided logger.
func NewProcessor(st store.Store, logger *slog.Logger, cfg ProcessorConfig) *Processor {
	if logger == nil {
		logger = slog.Default()
	}
	workers := cfg.EnqueueWorkers
	if workers <= 0 {
		workers = 1
	}
	return &Processor{
		store:          st,
		logger:         logger,
		enqueueWorkers: workers,
		notifier:       cfg.Notifier,
	}
}

// Process stores the SBOM, creates a revision, and updates ingest status/stage.
func (p *Processor) Process(input ProcessInput) (*ProcessResult, error) {
	if p == nil || p.store == nil {
		return nil, &ProcessError{Op: OpUpdateStage, Err: errors.New("store is nil")}
	}
	if input.JobID == uuid.Nil || input.TestID == uuid.Nil {
		return nil, &ProcessError{Op: OpUpdateStage, Err: errors.New("missing identifiers")}
	}

	if err := p.updateStage(input.JobID, store.IngestStageStoring, ""); err != nil {
		return nil, err
	}

	sbomFormat := strings.TrimSpace(input.SbomFormat)
	if sbomFormat == "" && strings.TrimSpace(input.SbomStandard) != "" {
		sbomFormat = sbom.FormatString(sbom.Type{
			Standard:    sbom.Standard(strings.ToLower(strings.TrimSpace(input.SbomStandard))),
			SpecVersion: strings.TrimSpace(input.SbomSpecVersion),
		})
	}
	if sbomFormat == "" {
		sbomFormat = "unknown"
	}
	if _, err := p.store.StoreSbom(input.SbomSha256, input.Payload, sbomFormat, input.ContentType, input.IsGzip); err != nil {
		if statusErr := p.updateStatus(input.JobID, store.IngestStatusFailed, err.Error()); statusErr != nil {
			return nil, statusErr
		}
		if stageErr := p.updateStage(input.JobID, store.IngestStageFailed, err.Error()); stageErr != nil {
			return nil, stageErr
		}
		return nil, &ProcessError{Op: OpStoreSbom, Err: err}
	}
	p.logger.Debug("sbom stored", "job_id", input.JobID, "sha256", input.SbomSha256)

	if err := p.updateStage(input.JobID, store.IngestStageRevisioning, ""); err != nil {
		return nil, err
	}

	componentsCount := input.ComponentsCount
	if len(input.Components) > 0 {
		componentsCount = len(input.Components)
	}
	revision, err := p.store.AddRevision(input.TestID, store.RevisionInput{
		SbomSha256:              input.SbomSha256,
		SbomProducer:            input.SbomProducer,
		Tags:                    input.Tags,
		MetadataJSON:            input.MetadataJSON,
		SbomMetadataJSON:        input.SbomMetadataJSON,
		ComponentsImportedCount: componentsCount,
		Components:              input.Components,
	})
	if err != nil {
		if statusErr := p.updateStatus(input.JobID, store.IngestStatusFailed, err.Error()); statusErr != nil {
			return nil, statusErr
		}
		if stageErr := p.updateStage(input.JobID, store.IngestStageFailed, err.Error()); stageErr != nil {
			return nil, stageErr
		}
		return nil, &ProcessError{Op: OpAddRevision, Err: err}
	}
	p.logger.Debug("revision stored", "job_id", input.JobID, "revision_id", revision.ID)
	if p.notifier != nil {
		p.notifier.NotifyWorkers()
	}

	if err := p.enqueueComponentAnalysis(input.Components); err != nil {
		if statusErr := p.updateStatus(input.JobID, store.IngestStatusFailed, err.Error()); statusErr != nil {
			return nil, statusErr
		}
		if stageErr := p.updateStage(input.JobID, store.IngestStageFailed, err.Error()); stageErr != nil {
			return nil, stageErr
		}
		return nil, &ProcessError{Op: OpEnqueueAnalysis, Err: err}
	}

	if err := p.updateStatus(input.JobID, store.IngestStatusCompleted, ""); err != nil {
		return nil, err
	}
	if err := p.updateStage(input.JobID, store.IngestStageCompleted, ""); err != nil {
		return nil, err
	}

	return &ProcessResult{Revision: revision}, nil
}

func (p *Processor) enqueueComponentAnalysis(components []store.ComponentInput) error {
	if p == nil || p.store == nil {
		return errors.New("store is nil")
	}
	if len(components) == 0 {
		return nil
	}
	purls := uniqueComponentPURLs(components)
	if len(purls) == 0 {
		return nil
	}

	workers := p.enqueueWorkers
	if workers <= 1 || len(purls) <= 1 {
		count, err := p.store.EnqueueComponentAnalysisBatch(purls, store.ComponentAnalysisReasonBackfill, nil)
		if err != nil {
			return err
		}
		if count > 0 && p.notifier != nil {
			p.notifier.NotifyWorkers()
		}
		return nil
	}

	chunks := chunkPURLs(purls, workers)
	var wg sync.WaitGroup
	errCh := make(chan error, len(chunks))
	countCh := make(chan int, len(chunks))
	for _, chunk := range chunks {
		wg.Add(1)
		go func(items []string) {
			defer wg.Done()
			count, err := p.store.EnqueueComponentAnalysisBatch(items, store.ComponentAnalysisReasonBackfill, nil)
			if err != nil {
				errCh <- err
				return
			}
			countCh <- count
		}(chunk)
	}
	wg.Wait()
	close(errCh)
	close(countCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}

	total := 0
	for count := range countCh {
		total += count
	}
	if total > 0 && p.notifier != nil {
		p.notifier.NotifyWorkers()
	}
	return nil
}

func uniqueComponentPURLs(components []store.ComponentInput) []string {
	seen := make(map[string]struct{}, len(components))
	purls := make([]string, 0, len(components))
	for _, component := range components {
		purl := strings.TrimSpace(component.PURL)
		if purl == "" {
			continue
		}
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}
		purls = append(purls, purl)
	}
	return purls
}

func chunkPURLs(purls []string, workers int) [][]string {
	if workers <= 1 || len(purls) == 0 {
		return [][]string{purls}
	}
	if workers > len(purls) {
		workers = len(purls)
	}
	chunks := make([][]string, 0, workers)
	step := (len(purls) + workers - 1) / workers
	for i := 0; i < len(purls); i += step {
		end := i + step
		if end > len(purls) {
			end = len(purls)
		}
		chunks = append(chunks, purls[i:end])
	}
	return chunks
}

func (p *Processor) updateStage(jobID uuid.UUID, stage string, errorMessage string) error {
	if err := p.store.UpdateIngestJobStage(jobID, stage, errorMessage); err != nil {
		return &ProcessError{Op: OpUpdateStage, Err: err}
	}
	p.logger.Debug("ingest stage updated", "job_id", jobID, "stage", stage)
	return nil
}

func (p *Processor) updateStatus(jobID uuid.UUID, status string, errorMessage string) error {
	if err := p.store.UpdateIngestJobStatus(jobID, status, errorMessage); err != nil {
		return &ProcessError{Op: OpUpdateStatus, Err: err}
	}
	p.logger.Debug("ingest status updated", "job_id", jobID, "status", status)
	return nil
}
