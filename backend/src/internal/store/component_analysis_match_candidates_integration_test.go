package store_test

import (
	"encoding/json"
	"strings"
	"testing"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListMalwareMatchCandidates_FiltersByPackageIdentity(t *testing.T) {
	storeInstance, _ := tests.NewPostgresTestStore(t)

	source, err := storeInstance.CreateScanMalwareSource("match-candidates-source", "OSV_API", "https://osv.example.local", nil, true)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	scanner, err := storeInstance.CreateScanner(source.ID, "match-candidates-scanner", "osv", "1.0.0", "", nil)
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}

	insertCandidate(t, storeInstance, scanner.ID, source.ID, "pkg:deb/debian/apt", "2.6.1", "mal-apt-base.json")
	insertCandidate(t, storeInstance, scanner.ID, source.ID, "pkg:deb/debian/apt@2.6.1", "", "mal-apt-versioned.json")
	insertCandidate(t, storeInstance, scanner.ID, source.ID, "pkg:deb/debian/aptitude@2.6.1", "2.6.1", "mal-aptitude.json")

	results, err := storeInstance.ListMalwareMatchCandidates("pkg:deb/debian/apt@2.6.1?arch=amd64&distro=debian-12")
	if err != nil {
		t.Fatalf("list candidates: %v", err)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one candidate")
	}

	foundApt := false
	foundAptitude := false
	foundDetails := false
	for _, candidate := range results {
		if strings.HasPrefix(candidate.ComponentPURL, "pkg:deb/debian/aptitude") {
			foundAptitude = true
		}
		if strings.HasPrefix(candidate.ComponentPURL, "pkg:deb/debian/apt") &&
			!strings.HasPrefix(candidate.ComponentPURL, "pkg:deb/debian/aptitude") {
			foundApt = true
			if len(candidate.DetailsJSON) != 0 {
				foundDetails = true
			}
		}
	}
	if !foundApt {
		t.Fatalf("expected apt candidates, got %#v", results)
	}
	if !foundDetails {
		t.Fatalf("expected details_json in apt candidate, got %#v", results)
	}
	if foundAptitude {
		t.Fatalf("unexpected aptitude candidate in %#v", results)
	}
}

func insertCandidate(t *testing.T, st *store.PostgresStore, scannerID, sourceID uuid.UUID, componentPURL, detectVersion, filename string) {
	t.Helper()
	queue, err := st.UpsertAnalysisQueue(componentPURL, scannerID, store.AnalysisStatusProcessing)
	if err != nil {
		t.Fatalf("upsert queue: %v", err)
	}

	input := store.ScanComponentResultInput{
		ComponentPURL:  componentPURL,
		ScanID:         queue.ID,
		SourceID:       sourceID,
		ResultFilename: filename,
		Evidence:       "fixture",
		DetailsJSON:    json.RawMessage(`{"id":"MAL-FIXTURE"}`),
		DetectVersion:  detectVersion,
		IsMalware:      true,
	}
	if _, err := st.UpsertScanComponentResult(input); err != nil {
		t.Fatalf("insert scan component result: %v", err)
	}

	result, err := st.UpsertAnalysisResultFromFindings(componentPURL, "", "fixture")
	if err != nil {
		t.Fatalf("upsert analysis result: %v", err)
	}
	input.AnalysisResultID = &result.ID
	if _, err := st.UpsertScanComponentResult(input); err != nil {
		t.Fatalf("link analysis result: %v", err)
	}
	if err := st.UpdateAnalysisQueueStatus(queue.ID, store.AnalysisStatusCompleted); err != nil {
		t.Fatalf("complete queue: %v", err)
	}
}
