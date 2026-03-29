package store

import "testing"

func TestAnalysisStatusTransitions(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{name: "pending to processing", from: AnalysisStatusPending, to: AnalysisStatusProcessing, want: true},
		{name: "pending to failed", from: AnalysisStatusPending, to: AnalysisStatusFailed, want: true},
		{name: "processing to completed", from: AnalysisStatusProcessing, to: AnalysisStatusCompleted, want: true},
		{name: "processing to failed", from: AnalysisStatusProcessing, to: AnalysisStatusFailed, want: true},
		{name: "failed to processing", from: AnalysisStatusFailed, to: AnalysisStatusProcessing, want: true},
		{name: "completed to completed", from: AnalysisStatusCompleted, to: AnalysisStatusCompleted, want: true},
		{name: "completed to processing", from: AnalysisStatusCompleted, to: AnalysisStatusProcessing, want: true},
		{name: "empty status", from: "", to: AnalysisStatusProcessing, want: false},
		{name: "invalid next", from: AnalysisStatusPending, to: "oops", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := analysisState.CanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestAnalysisStatusValidation(t *testing.T) {
	valid := []string{AnalysisStatusPending, AnalysisStatusProcessing, AnalysisStatusCompleted, AnalysisStatusFailed}
	for _, status := range valid {
		if !isValidAnalysisStatus(status) {
			t.Fatalf("expected status %s to be valid", status)
		}
	}
	if isValidAnalysisStatus("bad") {
		t.Fatalf("expected invalid status")
	}
}
