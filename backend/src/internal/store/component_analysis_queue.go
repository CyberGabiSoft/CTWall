package store

import "strings"

const (
	// ComponentAnalysisStatusPending indicates a queued component analysis job.
	ComponentAnalysisStatusPending = "PENDING"
	// ComponentAnalysisStatusProcessing indicates a component analysis job is running.
	ComponentAnalysisStatusProcessing = "PROCESSING"
	// ComponentAnalysisStatusCompleted indicates a component analysis job completed.
	ComponentAnalysisStatusCompleted = "COMPLETED"
	// ComponentAnalysisStatusFailed indicates a component analysis job failed.
	ComponentAnalysisStatusFailed = "FAILED"
)

const (
	// ComponentAnalysisReasonScheduled indicates a scheduler-triggered job.
	ComponentAnalysisReasonScheduled = "SCHEDULED"
	// ComponentAnalysisReasonManual indicates a user-triggered job.
	ComponentAnalysisReasonManual = "MANUAL"
	// ComponentAnalysisReasonBackfill indicates a job triggered by ingest backfill.
	ComponentAnalysisReasonBackfill = "BACKFILL"
)

const (
	// ComponentAnalysisMatchExact indicates exact PURL match.
	ComponentAnalysisMatchExact = "EXACT"
	// ComponentAnalysisMatchContainsPrefix indicates component PURL contains malware PURL with version suffix.
	ComponentAnalysisMatchContainsPrefix = "CONTAINS_PREFIX"
)

type componentAnalysisStateMachine struct {
	transitions map[string]map[string]struct{}
}

func newComponentAnalysisStateMachine() componentAnalysisStateMachine {
	return componentAnalysisStateMachine{
		transitions: map[string]map[string]struct{}{
			ComponentAnalysisStatusPending: {
				ComponentAnalysisStatusProcessing: {},
				ComponentAnalysisStatusFailed:     {},
			},
			ComponentAnalysisStatusProcessing: {
				ComponentAnalysisStatusCompleted: {},
				ComponentAnalysisStatusFailed:    {},
			},
			ComponentAnalysisStatusFailed: {
				ComponentAnalysisStatusProcessing: {},
			},
			ComponentAnalysisStatusCompleted: {},
		},
	}
}

func (sm componentAnalysisStateMachine) CanTransition(from string, to string) bool {
	current := normalizeComponentAnalysisStatus(from)
	next := normalizeComponentAnalysisStatus(to)
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

var componentAnalysisState = newComponentAnalysisStateMachine()

func normalizeComponentAnalysisStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

func isValidComponentAnalysisStatus(status string) bool {
	switch normalizeComponentAnalysisStatus(status) {
	case ComponentAnalysisStatusPending, ComponentAnalysisStatusProcessing, ComponentAnalysisStatusCompleted, ComponentAnalysisStatusFailed:
		return true
	default:
		return false
	}
}

func normalizeComponentAnalysisReason(reason string) string {
	return strings.ToUpper(strings.TrimSpace(reason))
}

func isValidComponentAnalysisReason(reason string) bool {
	switch normalizeComponentAnalysisReason(reason) {
	case ComponentAnalysisReasonScheduled, ComponentAnalysisReasonManual, ComponentAnalysisReasonBackfill:
		return true
	default:
		return false
	}
}

func normalizeComponentAnalysisMatchType(matchType string) string {
	return strings.ToUpper(strings.TrimSpace(matchType))
}

func isValidComponentAnalysisMatchType(matchType string) bool {
	switch normalizeComponentAnalysisMatchType(matchType) {
	case ComponentAnalysisMatchExact, ComponentAnalysisMatchContainsPrefix:
		return true
	default:
		return false
	}
}
