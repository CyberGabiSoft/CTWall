package store_test

import (
	"testing"
	"time"

	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListAnalysisResultsForComponentMatch_BasePURLMatchUsesIndexableCandidates(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	base := "pkg:npm/@angular/core"
	component := "pkg:npm/@angular/core@16.0.0"
	id := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, component_hash, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, '', 'MALWARE', 1, 'test', $3)`,
		id,
		base,
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}

	results, err := storeInstance.ListAnalysisResultsForComponentMatch(component)
	if err != nil {
		t.Fatalf("list analysis results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != id {
		t.Fatalf("expected id=%s, got %s", id, results[0].ID)
	}
	if results[0].ComponentPURL != base {
		t.Fatalf("expected component_purl=%q, got %q", base, results[0].ComponentPURL)
	}
}

func TestListAnalysisResultsForComponentMatch_NullComponentHashAndSummaryHandled(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	base := "pkg:deb/debian/apt"
	component := "pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12"
	id := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, component_hash, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, NULL, 'CLEAN', 0, NULL, $3)`,
		id,
		base,
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}

	results, err := storeInstance.ListAnalysisResultsForComponentMatch(component)
	if err != nil {
		t.Fatalf("list analysis results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != id {
		t.Fatalf("expected id=%s, got %s", id, results[0].ID)
	}
	if results[0].ComponentPURL != base {
		t.Fatalf("expected component_purl=%q, got %q", base, results[0].ComponentPURL)
	}
	if results[0].ComponentHash != "" {
		t.Fatalf("expected empty component_hash for NULL db value, got %q", results[0].ComponentHash)
	}
	if results[0].Summary != "" {
		t.Fatalf("expected empty summary for NULL db value, got %q", results[0].Summary)
	}
}
