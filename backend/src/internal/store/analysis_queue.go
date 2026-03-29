package store

import "strings"

const (
	// AnalysisStatusPending indicates a queued analysis job.
	AnalysisStatusPending = "PENDING"
	// AnalysisStatusProcessing indicates a job currently processing.
	AnalysisStatusProcessing = "PROCESSING"
	// AnalysisStatusCompleted indicates analysis completed.
	AnalysisStatusCompleted = "COMPLETED"
	// AnalysisStatusFailed indicates analysis failed.
	AnalysisStatusFailed = "FAILED"
)

type analysisStateMachine struct {
	transitions map[string]map[string]struct{}
}

func newAnalysisStateMachine() analysisStateMachine {
	return analysisStateMachine{
		transitions: map[string]map[string]struct{}{
			AnalysisStatusPending: {
				AnalysisStatusProcessing: {},
				AnalysisStatusFailed:     {},
			},
			AnalysisStatusProcessing: {
				AnalysisStatusCompleted: {},
				AnalysisStatusFailed:    {},
			},
			AnalysisStatusFailed: {
				AnalysisStatusProcessing: {},
			},
			AnalysisStatusCompleted: {
				AnalysisStatusProcessing: {},
			},
		},
	}
}

func (sm analysisStateMachine) CanTransition(from string, to string) bool {
	current := normalizeAnalysisStatus(from)
	next := normalizeAnalysisStatus(to)
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

var analysisState = newAnalysisStateMachine()

func normalizeAnalysisStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

func isValidAnalysisStatus(status string) bool {
	switch normalizeAnalysisStatus(status) {
	case AnalysisStatusPending, AnalysisStatusProcessing, AnalysisStatusCompleted, AnalysisStatusFailed:
		return true
	default:
		return false
	}
}

func isValidMalwareSourceType(sourceType string) bool {
	switch strings.ToUpper(strings.TrimSpace(sourceType)) {
	case "OSV_API", "OSV_MIRROR", "GITHUB_ADVISORIES":
		return true
	default:
		return false
	}
}

func normalizeMalwareSourceType(sourceType string) string {
	return strings.ToUpper(strings.TrimSpace(sourceType))
}

func isValidAnalysisVerdict(verdict string) bool {
	switch strings.ToUpper(strings.TrimSpace(verdict)) {
	case "MALWARE", "CLEAN", "UNKNOWN":
		return true
	default:
		return false
	}
}

func normalizeAnalysisVerdict(verdict string) string {
	return strings.ToUpper(strings.TrimSpace(verdict))
}
