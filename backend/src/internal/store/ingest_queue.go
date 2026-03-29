package store

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// IngestStatusPending indicates a queued ingest job.
	IngestStatusPending = "PENDING"
	// IngestStatusProcessing indicates an ingest job is being processed.
	IngestStatusProcessing = "PROCESSING"
	// IngestStatusCompleted indicates an ingest job completed successfully.
	IngestStatusCompleted = "COMPLETED"
	// IngestStatusFailed indicates an ingest job failed.
	IngestStatusFailed = "FAILED"
)

const (
	// IngestStageReceived indicates the ingest job was created.
	IngestStageReceived = "RECEIVED"
	// IngestStageValidating indicates input validation is running.
	IngestStageValidating = "VALIDATING"
	// IngestStageParsing indicates SBOM parsing is running.
	IngestStageParsing = "PARSING"
	// IngestStageAnalyzing indicates SBOM analysis is running.
	IngestStageAnalyzing = "ANALYZING"
	// IngestStageStoring indicates SBOM persistence is running.
	IngestStageStoring = "STORING"
	// IngestStageRevisioning indicates revision creation is running.
	IngestStageRevisioning = "REVISIONING"
	// IngestStageCompleted indicates ingest processing completed.
	IngestStageCompleted = "COMPLETED"
	// IngestStageFailed indicates ingest processing failed.
	IngestStageFailed = "FAILED"
)

// IngestRequest stores the raw input fields for an ingest job.
type IngestRequest struct {
	ProductID       *uuid.UUID
	ScopeID         *uuid.UUID
	TestID          *uuid.UUID
	SbomSha256      string
	SbomStandard    string
	SbomSpecVersion string
	SbomProducer    string
	Tags            []string
	MetadataJSON    json.RawMessage
	ContentType     string
	IsGzip          bool
	ComponentsCount int
}

// IngestJob represents a persisted ingest queue item.
type IngestJob struct {
	ID              uuid.UUID
	Status          string
	ProcessingStage string
	ErrorMessage    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CompletedAt     *time.Time
	IngestRequest
}

type ingestStateMachine struct {
	transitions map[string]map[string]struct{}
}

func newIngestStateMachine() ingestStateMachine {
	return ingestStateMachine{
		transitions: map[string]map[string]struct{}{
			IngestStatusPending: {
				IngestStatusProcessing: {},
				IngestStatusFailed:     {},
			},
			IngestStatusProcessing: {
				IngestStatusCompleted: {},
				IngestStatusFailed:    {},
			},
			IngestStatusFailed: {
				IngestStatusProcessing: {},
			},
			IngestStatusCompleted: {},
		},
	}
}

func (sm ingestStateMachine) CanTransition(from string, to string) bool {
	current := normalizeIngestStatus(from)
	next := normalizeIngestStatus(to)
	if current == "" || next == "" {
		return false
	}
	if current == next {
		return true
	}
	allowed := sm.transitions[current]
	if allowed == nil {
		return false
	}
	_, ok := allowed[next]
	return ok
}

var ingestState = newIngestStateMachine()

func normalizeIngestStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

func isValidIngestStatus(status string) bool {
	switch normalizeIngestStatus(status) {
	case IngestStatusPending, IngestStatusProcessing, IngestStatusCompleted, IngestStatusFailed:
		return true
	default:
		return false
	}
}

type ingestStageMachine struct {
	transitions map[string]map[string]struct{}
}

func newIngestStageMachine() ingestStageMachine {
	return ingestStageMachine{
		transitions: map[string]map[string]struct{}{
			IngestStageReceived: {
				IngestStageValidating: {},
				IngestStageFailed:     {},
			},
			IngestStageValidating: {
				IngestStageParsing: {},
				IngestStageFailed:  {},
			},
			IngestStageParsing: {
				IngestStageAnalyzing: {},
				IngestStageFailed:    {},
			},
			IngestStageAnalyzing: {
				IngestStageStoring: {},
				IngestStageFailed:  {},
			},
			IngestStageStoring: {
				IngestStageRevisioning: {},
				IngestStageFailed:      {},
			},
			IngestStageRevisioning: {
				IngestStageCompleted: {},
				IngestStageFailed:    {},
			},
			IngestStageFailed: {
				IngestStageValidating: {},
			},
			IngestStageCompleted: {},
		},
	}
}

func (sm ingestStageMachine) CanTransition(from string, to string) bool {
	current := normalizeIngestStage(from)
	next := normalizeIngestStage(to)
	if current == "" || next == "" {
		return false
	}
	if current == next {
		return true
	}
	allowed := sm.transitions[current]
	if allowed == nil {
		return false
	}
	_, ok := allowed[next]
	return ok
}

var ingestStage = newIngestStageMachine()

func normalizeIngestStage(stage string) string {
	return strings.ToUpper(strings.TrimSpace(stage))
}

func isValidIngestStage(stage string) bool {
	switch normalizeIngestStage(stage) {
	case IngestStageReceived, IngestStageValidating, IngestStageParsing, IngestStageAnalyzing,
		IngestStageStoring, IngestStageRevisioning, IngestStageCompleted, IngestStageFailed:
		return true
	default:
		return false
	}
}
