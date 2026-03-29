package store

import "strings"

const (
	// TestRevisionFindingDiffStatusPending indicates an enqueued revision-diff job.
	TestRevisionFindingDiffStatusPending = "PENDING"
	// TestRevisionFindingDiffStatusProcessing indicates a revision-diff job is running.
	TestRevisionFindingDiffStatusProcessing = "PROCESSING"
	// TestRevisionFindingDiffStatusCompleted indicates a revision-diff job completed successfully.
	TestRevisionFindingDiffStatusCompleted = "COMPLETED"
	// TestRevisionFindingDiffStatusFailed indicates a revision-diff job failed.
	TestRevisionFindingDiffStatusFailed = "FAILED"
)

const (
	// TestRevisionFindingDiffReasonIngest indicates enqueue due to new SBOM revision ingest.
	TestRevisionFindingDiffReasonIngest = "INGEST"
	// TestRevisionFindingDiffReasonBackfill indicates enqueue due to migration/backfill.
	TestRevisionFindingDiffReasonBackfill = "BACKFILL"
	// TestRevisionFindingDiffReasonManual indicates enqueue due to manual action.
	TestRevisionFindingDiffReasonManual = "MANUAL"
)

const (
	// TestRevisionFindingTypeMalware identifies malware finding diffs.
	TestRevisionFindingTypeMalware = "MALWARE"
)

const (
	// TestRevisionFindingDiffTypeAdded marks findings present only in the new revision.
	TestRevisionFindingDiffTypeAdded = "ADDED"
	// TestRevisionFindingDiffTypeRemoved marks findings present only in the previous revision.
	TestRevisionFindingDiffTypeRemoved = "REMOVED"
	// TestRevisionFindingDiffTypeUnchanged marks findings present in both revisions.
	TestRevisionFindingDiffTypeUnchanged = "UNCHANGED"
	// TestRevisionFindingDiffTypeReappeared marks a previously closed finding that reappeared.
	TestRevisionFindingDiffTypeReappeared = "REAPPEARED"
)

type testRevisionFindingDiffStateMachine struct {
	transitions map[string]map[string]struct{}
}

func newTestRevisionFindingDiffStateMachine() testRevisionFindingDiffStateMachine {
	return testRevisionFindingDiffStateMachine{
		transitions: map[string]map[string]struct{}{
			TestRevisionFindingDiffStatusPending: {
				TestRevisionFindingDiffStatusProcessing: {},
				TestRevisionFindingDiffStatusFailed:     {},
			},
			TestRevisionFindingDiffStatusProcessing: {
				TestRevisionFindingDiffStatusCompleted: {},
				TestRevisionFindingDiffStatusFailed:    {},
			},
			TestRevisionFindingDiffStatusFailed: {
				TestRevisionFindingDiffStatusProcessing: {},
			},
			TestRevisionFindingDiffStatusCompleted: {},
		},
	}
}

func (sm testRevisionFindingDiffStateMachine) CanTransition(from string, to string) bool {
	current := normalizeTestRevisionFindingDiffStatus(from)
	next := normalizeTestRevisionFindingDiffStatus(to)
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

var testRevisionFindingDiffState = newTestRevisionFindingDiffStateMachine()

func normalizeTestRevisionFindingDiffStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

func isValidTestRevisionFindingDiffStatus(status string) bool {
	switch normalizeTestRevisionFindingDiffStatus(status) {
	case TestRevisionFindingDiffStatusPending,
		TestRevisionFindingDiffStatusProcessing,
		TestRevisionFindingDiffStatusCompleted,
		TestRevisionFindingDiffStatusFailed:
		return true
	default:
		return false
	}
}

func normalizeTestRevisionFindingDiffReason(reason string) string {
	return strings.ToUpper(strings.TrimSpace(reason))
}

func isValidTestRevisionFindingDiffReason(reason string) bool {
	switch normalizeTestRevisionFindingDiffReason(reason) {
	case TestRevisionFindingDiffReasonIngest,
		TestRevisionFindingDiffReasonBackfill,
		TestRevisionFindingDiffReasonManual:
		return true
	default:
		return false
	}
}

func normalizeTestRevisionFindingDiffType(diffType string) string {
	return strings.ToUpper(strings.TrimSpace(diffType))
}

func isValidTestRevisionFindingDiffType(diffType string) bool {
	switch normalizeTestRevisionFindingDiffType(diffType) {
	case TestRevisionFindingDiffTypeAdded,
		TestRevisionFindingDiffTypeRemoved,
		TestRevisionFindingDiffTypeUnchanged,
		TestRevisionFindingDiffTypeReappeared:
		return true
	default:
		return false
	}
}
