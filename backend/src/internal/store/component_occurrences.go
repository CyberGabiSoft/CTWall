package store

import (
	"time"

	"github.com/google/uuid"
)

// ComponentOccurrence represents a single occurrence of a Component (from an active TestRevision)
// enriched with Product/Scope/Test context and malware verdict.
type ComponentOccurrence struct {
	ComponentID          uuid.UUID
	RevisionID           uuid.UUID
	PURL                 string
	PkgName              string
	Version              string
	PkgType              string
	PkgNamespace         string
	CreatedAt            time.Time
	TestID               uuid.UUID
	TestName             string
	ScopeID              uuid.UUID
	ScopeName            string
	ProductID            uuid.UUID
	ProductName          string
	MalwareVerdict       string
	MalwareFindingsCount int
	MalwareScannedAt     *time.Time
	MalwareValidUntil    *time.Time
}
