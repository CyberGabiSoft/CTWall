package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultDataGraphMaxNodes limits response size for dependency graph chain.
	DefaultDataGraphMaxNodes = 1200
	// MaxDataGraphMaxNodes is the hard upper bound accepted by the API.
	MaxDataGraphMaxNodes = 5000
	// DefaultDataGraphRowsLimit is used for details sublists (occurrences/findings/history).
	DefaultDataGraphRowsLimit = 50
	// MaxDataGraphRowsLimit is the hard cap for details sublists.
	MaxDataGraphRowsLimit = 200
)

// DataGraphComponentRecord describes a component in a specific revision with hierarchy context.
type DataGraphComponentRecord struct {
	ID           uuid.UUID       `json:"id"`
	RevisionID   uuid.UUID       `json:"revisionId"`
	PURL         string          `json:"purl"`
	PkgName      string          `json:"pkgName"`
	Version      string          `json:"version"`
	PkgType      string          `json:"pkgType"`
	PkgNamespace string          `json:"pkgNamespace,omitempty"`
	SbomType     string          `json:"sbomType,omitempty"`
	Publisher    string          `json:"publisher,omitempty"`
	Supplier     string          `json:"supplier,omitempty"`
	Licenses     json.RawMessage `json:"licenses,omitempty"`
	Properties   json.RawMessage `json:"properties,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`

	ProjectID   uuid.UUID `json:"projectId"`
	ProjectName string    `json:"projectName"`
	ProductID   uuid.UUID `json:"productId"`
	ProductName string    `json:"productName"`
	ScopeID     uuid.UUID `json:"scopeId"`
	ScopeName   string    `json:"scopeName"`
	TestID      uuid.UUID `json:"testId"`
	TestName    string    `json:"testName"`

	SbomStandard      string    `json:"sbomStandard"`
	SbomSpecVersion   string    `json:"sbomSpecVersion"`
	SbomProducer      string    `json:"sbomProducer"`
	RevisionIsActive  bool      `json:"revisionIsActive"`
	RevisionCreatedAt time.Time `json:"revisionCreatedAt"`
}

// DataGraphComponentOccurrence describes where a component appears in the current project.
type DataGraphComponentOccurrence struct {
	ProductID         uuid.UUID `json:"productId"`
	ProductName       string    `json:"productName"`
	ScopeID           uuid.UUID `json:"scopeId"`
	ScopeName         string    `json:"scopeName"`
	TestID            uuid.UUID `json:"testId"`
	TestName          string    `json:"testName"`
	RevisionID        uuid.UUID `json:"revisionId"`
	RevisionIsActive  bool      `json:"revisionIsActive"`
	RevisionCreatedAt time.Time `json:"revisionCreatedAt"`
	SbomProducer      string    `json:"sbomProducer"`
}

// DataGraphComponentFinding describes malware mapping + triage for a component in test context.
type DataGraphComponentFinding struct {
	ID                         uuid.UUID  `json:"id"`
	ComponentPURL              string     `json:"componentPurl"`
	MalwarePURL                string     `json:"malwarePurl"`
	SourceMalwareInputResultID uuid.UUID  `json:"sourceMalwareInputResultId"`
	MatchType                  string     `json:"matchType"`
	CreatedAt                  time.Time  `json:"createdAt"`
	UpdatedAt                  time.Time  `json:"updatedAt"`
	TriageStatus               string     `json:"triageStatus"`
	TriagePriority             *string    `json:"triagePriority,omitempty"`
	EffectivePriority          string     `json:"effectivePriority"`
	TriageReason               *string    `json:"triageReason,omitempty"`
	TriageExpiresAt            *time.Time `json:"triageExpiresAt,omitempty"`
	TriageUpdatedAt            *time.Time `json:"triageUpdatedAt,omitempty"`
}
