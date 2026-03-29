package store

import (
	"time"

	"github.com/google/uuid"
)

const (
	DepAlertVerdictMalware = "MALWARE"
	DepAlertVerdictClean   = "CLEAN"
	DepAlertVerdictUnknown = "UNKNOWN"
)

// DepAlertRevisionVerdict represents revision-level malware verdict counters.
type DepAlertRevisionVerdict struct {
	ProjectID         uuid.UUID `json:"projectId"`
	TestID            uuid.UUID `json:"testId"`
	RevisionID        uuid.UUID `json:"revisionId"`
	Verdict           string    `json:"verdict"`
	TotalComponents   int       `json:"totalComponents"`
	MalwareComponents int       `json:"malwareComponents"`
	CleanComponents   int       `json:"cleanComponents"`
	UnknownComponents int       `json:"unknownComponents"`
	ComputedAt        time.Time `json:"computedAt"`
}
