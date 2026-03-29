package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AnalysisResultInput represents the fields required to create an analysis result.
type AnalysisResultInput struct {
	ComponentPURL string
	ComponentHash string
	Verdict       string
	FindingsCount int
	Summary       string
	ScannedAt     *time.Time
	ValidUntil    *time.Time
}

// ScanComponentResultInput represents the fields required to create a scan component result.
type ScanComponentResultInput struct {
	ComponentPURL    string
	ComponentHash    string
	AnalysisResultID *uuid.UUID
	ScanID           uuid.UUID
	SourceID         uuid.UUID
	ResultFilename   string
	Evidence         string
	DetailsJSON      json.RawMessage
	PublishedAt      *time.Time
	ModifiedAt       *time.Time
	DetectVersion    string
	FixedVersion     string
	IsMalware        bool
}

// ComponentAnalysisFindingInput represents the fields required to upsert a component analysis mapping.
type ComponentAnalysisFindingInput struct {
	ComponentPURL              string
	MalwarePURL                string
	SourceMalwareInputResultID uuid.UUID
	MatchType                  string
}
