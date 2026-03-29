package store

import "testing"

func TestIngestStateTransitions(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{name: "pending to processing", from: IngestStatusPending, to: IngestStatusProcessing, want: true},
		{name: "pending to failed", from: IngestStatusPending, to: IngestStatusFailed, want: true},
		{name: "processing to completed", from: IngestStatusProcessing, to: IngestStatusCompleted, want: true},
		{name: "processing to failed", from: IngestStatusProcessing, to: IngestStatusFailed, want: true},
		{name: "failed to processing", from: IngestStatusFailed, to: IngestStatusProcessing, want: true},
		{name: "completed to completed", from: IngestStatusCompleted, to: IngestStatusCompleted, want: true},
		{name: "completed to processing", from: IngestStatusCompleted, to: IngestStatusProcessing, want: false},
		{name: "empty status", from: "", to: IngestStatusProcessing, want: false},
		{name: "invalid next", from: IngestStatusPending, to: "oops", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ingestState.CanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestIngestStageTransitions(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{name: "received to validating", from: IngestStageReceived, to: IngestStageValidating, want: true},
		{name: "validating to parsing", from: IngestStageValidating, to: IngestStageParsing, want: true},
		{name: "parsing to analyzing", from: IngestStageParsing, to: IngestStageAnalyzing, want: true},
		{name: "analyzing to storing", from: IngestStageAnalyzing, to: IngestStageStoring, want: true},
		{name: "storing to revisioning", from: IngestStageStoring, to: IngestStageRevisioning, want: true},
		{name: "revisioning to completed", from: IngestStageRevisioning, to: IngestStageCompleted, want: true},
		{name: "validating to failed", from: IngestStageValidating, to: IngestStageFailed, want: true},
		{name: "failed to validating", from: IngestStageFailed, to: IngestStageValidating, want: true},
		{name: "completed to completed", from: IngestStageCompleted, to: IngestStageCompleted, want: true},
		{name: "completed to parsing", from: IngestStageCompleted, to: IngestStageParsing, want: false},
		{name: "empty stage", from: "", to: IngestStageValidating, want: false},
		{name: "invalid next", from: IngestStageReceived, to: "oops", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ingestStage.CanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
