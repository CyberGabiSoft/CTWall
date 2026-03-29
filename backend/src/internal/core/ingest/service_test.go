package ingest

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

type spyStore struct {
	store.Store
	base       store.Store
	stages     []string
	statuses   []string
	storeErr   error
	addErr     error
	failStatus string
}

const testSBOMSHA = "sha1"

func newSpyStore(t *testing.T) *spyStore {
	pgStore, _ := tests.NewPostgresTestStore(t)
	return &spyStore{Store: pgStore, base: pgStore}
}

func (s *spyStore) UpdateIngestJobStage(id uuid.UUID, stage string, errorMessage string) error {
	s.stages = append(s.stages, stage)
	return s.base.UpdateIngestJobStage(id, stage, errorMessage)
}

func (s *spyStore) UpdateIngestJobStatus(id uuid.UUID, status string, errorMessage string) error {
	if s.failStatus != "" && status == s.failStatus {
		return errors.New("status failure")
	}
	s.statuses = append(s.statuses, status)
	return s.base.UpdateIngestJobStatus(id, status, errorMessage)
}

func (s *spyStore) StoreSbom(sha string, data []byte, format string, contentType string, isGzip bool) (*store.SbomObject, error) {
	if s.storeErr != nil {
		return nil, s.storeErr
	}
	return s.base.StoreSbom(sha, data, format, contentType, isGzip)
}

func (s *spyStore) AddRevision(testID uuid.UUID, input store.RevisionInput) (*models.TestRevision, error) {
	if s.addErr != nil {
		return nil, s.addErr
	}
	return s.base.AddRevision(testID, input)
}

func prepareJob(t *testing.T, s *spyStore) (*store.IngestJob, uuid.UUID) {
	t.Helper()

	product, err := s.CreateProduct("Prod", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := s.CreateScope(product.ID, "Scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := s.EnsureTest(scope.ID, "Test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}
	job, err := s.CreateIngestJob(store.IngestRequest{
		ProductID:       &product.ID,
		ScopeID:         &scope.ID,
		TestID:          &testItem.ID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
	})
	if err != nil {
		t.Fatalf("create ingest job: %v", err)
	}
	if err := s.base.UpdateIngestJobStage(job.ID, store.IngestStageValidating, ""); err != nil {
		t.Fatalf("stage validating: %v", err)
	}
	if err := s.base.UpdateIngestJobStage(job.ID, store.IngestStageParsing, ""); err != nil {
		t.Fatalf("stage parsing: %v", err)
	}
	if err := s.base.UpdateIngestJobStage(job.ID, store.IngestStageAnalyzing, ""); err != nil {
		t.Fatalf("stage analyzing: %v", err)
	}
	if err := s.base.UpdateIngestJobStatus(job.ID, store.IngestStatusProcessing, ""); err != nil {
		t.Fatalf("status processing: %v", err)
	}

	return job, testItem.ID
}

func newProcessorForTests(st store.Store) *Processor {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewProcessor(st, logger, ProcessorConfig{EnqueueWorkers: 1})
}

func TestProcessorProcessSuccess(t *testing.T) {
	spy := newSpyStore(t)
	job, testID := prepareJob(t, spy)

	processor := newProcessorForTests(spy)
	result, err := processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Tags:            []string{"alpha"},
		ContentType:     "application/json",
		ComponentsCount: 1,
		Payload:         []byte(`{"components":[]}`),
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if result == nil || result.Revision == nil {
		t.Fatalf("expected revision result")
	}
	revisions, err := spy.ListRevisions(testID)
	if err != nil || len(revisions) != 1 {
		t.Fatalf("expected revision in store")
	}
	if len(spy.stages) != 3 ||
		spy.stages[0] != store.IngestStageStoring ||
		spy.stages[1] != store.IngestStageRevisioning ||
		spy.stages[2] != store.IngestStageCompleted {
		t.Fatalf("unexpected stage updates: %v", spy.stages)
	}
	if len(spy.statuses) != 1 || spy.statuses[0] != store.IngestStatusCompleted {
		t.Fatalf("unexpected status updates: %v", spy.statuses)
	}
}

func TestProcessorStoreSbomFailure(t *testing.T) {
	spy := newSpyStore(t)
	job, testID := prepareJob(t, spy)
	spy.storeErr = errors.New("sbom failure")

	processor := newProcessorForTests(spy)
	_, err := processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Payload:         []byte(`{"components":[]}`),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	var procErr *ProcessError
	if !errors.As(err, &procErr) || procErr.Op != OpStoreSbom {
		t.Fatalf("expected store sbom error, got %v", err)
	}
	if len(spy.statuses) != 1 || spy.statuses[0] != store.IngestStatusFailed {
		t.Fatalf("expected failed status update, got %v", spy.statuses)
	}
	if len(spy.stages) != 2 ||
		spy.stages[0] != store.IngestStageStoring ||
		spy.stages[1] != store.IngestStageFailed {
		t.Fatalf("unexpected stage updates: %v", spy.stages)
	}
	revisions, err := spy.ListRevisions(testID)
	if err != nil || len(revisions) != 0 {
		t.Fatalf("expected no revisions")
	}
}

func TestProcessorAddRevisionFailure(t *testing.T) {
	spy := newSpyStore(t)
	job, testID := prepareJob(t, spy)
	spy.addErr = errors.New("revision failure")

	processor := newProcessorForTests(spy)
	_, err := processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Payload:         []byte(`{"components":[]}`),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	var procErr *ProcessError
	if !errors.As(err, &procErr) || procErr.Op != OpAddRevision {
		t.Fatalf("expected add revision error, got %v", err)
	}
	if len(spy.statuses) != 1 || spy.statuses[0] != store.IngestStatusFailed {
		t.Fatalf("expected failed status update, got %v", spy.statuses)
	}
	if len(spy.stages) != 3 ||
		spy.stages[0] != store.IngestStageStoring ||
		spy.stages[1] != store.IngestStageRevisioning ||
		spy.stages[2] != store.IngestStageFailed {
		t.Fatalf("unexpected stage updates: %v", spy.stages)
	}
	revisions, err := spy.ListRevisions(testID)
	if err != nil || len(revisions) != 0 {
		t.Fatalf("expected no revisions")
	}
}

func TestProcessorUpdateStageFailure(t *testing.T) {
	spy := newSpyStore(t)
	product, err := spy.CreateProduct("Prod", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := spy.CreateScope(product.ID, "Scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := spy.EnsureTest(scope.ID, "Test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}
	job, err := spy.CreateIngestJob(store.IngestRequest{
		ProductID:       &product.ID,
		ScopeID:         &scope.ID,
		TestID:          &testItem.ID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
	})
	if err != nil {
		t.Fatalf("create ingest job: %v", err)
	}
	if err := spy.base.UpdateIngestJobStatus(job.ID, store.IngestStatusProcessing, ""); err != nil {
		t.Fatalf("status processing: %v", err)
	}

	processor := newProcessorForTests(spy)
	_, err = processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testItem.ID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Payload:         []byte(`{"components":[]}`),
	})
	if err == nil {
		t.Fatalf("expected stage error")
	}
	var procErr *ProcessError
	if !errors.As(err, &procErr) || procErr.Op != OpUpdateStage {
		t.Fatalf("expected update stage error, got %v", err)
	}
}

func TestProcessorUpdateStatusFailure(t *testing.T) {
	spy := newSpyStore(t)
	job, testID := prepareJob(t, spy)
	spy.failStatus = store.IngestStatusCompleted

	processor := newProcessorForTests(spy)
	_, err := processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Payload:         []byte(`{"components":[]}`),
	})
	if err == nil {
		t.Fatalf("expected status error")
	}
	var procErr *ProcessError
	if !errors.As(err, &procErr) || procErr.Op != OpUpdateStatus {
		t.Fatalf("expected update status error, got %v", err)
	}
	if len(spy.stages) < 2 {
		t.Fatalf("expected stage updates before status failure")
	}
}

func TestProcessorUpdateStatusFailureOnStoreError(t *testing.T) {
	spy := newSpyStore(t)
	job, testID := prepareJob(t, spy)
	spy.storeErr = errors.New("sbom failure")
	spy.failStatus = store.IngestStatusFailed

	processor := newProcessorForTests(spy)
	_, err := processor.Process(ProcessInput{
		JobID:           job.ID,
		TestID:          testID,
		SbomSha256:      testSBOMSHA,
		SbomStandard:    "cyclonedx",
		SbomSpecVersion: "1.6",
		SbomProducer:    "syft",
		Payload:         []byte(`{"components":[]}`),
	})
	if err == nil {
		t.Fatalf("expected status error")
	}
	var procErr *ProcessError
	if !errors.As(err, &procErr) || procErr.Op != OpUpdateStatus {
		t.Fatalf("expected update status error, got %v", err)
	}
}
