package componentanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backend/internal/models"
	"backend/internal/sbom"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestProcessJob_PURLVersionSmart_UsesTrivyFixture(t *testing.T) {
	memStore, _ := tests.NewPostgresTestStore(t)

	doc := parseTrivyFixture(t)
	componentVersioned := findComponentPURL(t, doc, "pkg:deb/debian/apt@2.6.1")
	componentNoVersion := findComponentPURL(t, doc, "pkg:golang/example.com/go-app")

	source, err := memStore.CreateScanMalwareSource("Fixture OSV Source", "OSV_API", "https://osv.example.local", nil, true)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	scanner, err := memStore.CreateScanner(source.ID, "fixture-osv", "osv", "1.0.0", "", nil)
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}

	// A: component with version -> exact purl+version match using OSV affected[].versions.
	insertFixtureMalwareFinding(
		t,
		memStore,
		scanner.ID,
		source.ID,
		"pkg:deb/debian/apt",
		"2.6.1",
		"MAL-APT.json",
		json.RawMessage(`{
			"id":"MAL-APT",
			"affected":[
				{"package":{"purl":"pkg:deb/debian/apt"},"versions":["2.6.1","2.7.0"]}
			]
		}`),
	)

	// B: component without version -> prefix fallback.
	insertFixtureMalwareFinding(
		t,
		memStore,
		scanner.ID,
		source.ID,
		"pkg:golang/example.com/go-app",
		"",
		"MAL-GOAPP.json",
		json.RawMessage(`{
			"id":"MAL-GOAPP",
			"affected":[
				{"package":{"purl":"pkg:golang/example.com/go-app"},"versions":["1.2.3","1.2.4"]}
			]
		}`),
	)

	svc := NewService(memStore, nil)

	if err := svc.processJob(context.Background(), componentVersioned); err != nil {
		t.Fatalf("process versioned component: %v", err)
	}
	if err := svc.processJob(context.Background(), componentNoVersion); err != nil {
		t.Fatalf("process non-versioned component: %v", err)
	}

	findingsVersioned, err := memStore.ListComponentAnalysisFindings(componentVersioned)
	if err != nil {
		t.Fatalf("list findings versioned: %v", err)
	}
	assertFinding(t, findingsVersioned, "pkg:deb/debian/apt@2.6.1", store.ComponentAnalysisMatchExact)

	findingsNoVersion, err := memStore.ListComponentAnalysisFindings(componentNoVersion)
	if err != nil {
		t.Fatalf("list findings no-version: %v", err)
	}
	assertFinding(t, findingsNoVersion, "pkg:golang/example.com/go-app", store.ComponentAnalysisMatchContainsPrefix)
}

func TestProcessJob_PURLVersionSmart_UsesOSVVersionsList(t *testing.T) {
	memStore, _ := tests.NewPostgresTestStore(t)

	doc := parseTrivyFixture(t)
	componentVersioned := findComponentPURL(t, doc, "pkg:deb/debian/apt@2.6.1")

	source, err := memStore.CreateScanMalwareSource("Fixture OSV Source", "OSV_API", "https://osv.example.local", nil, true)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	scanner, err := memStore.CreateScanner(source.ID, "fixture-osv", "osv", "1.0.0", "", nil)
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}

	multiVersionDetails := json.RawMessage(`{
		"id":"MAL-APT-VERSIONS",
		"affected":[
			{"package":{"purl":"pkg:deb/debian/apt"},"versions":["2.5.0","2.6.1","2.7.0"]}
		]
	}`)
	insertFixtureMalwareFinding(
		t,
		memStore,
		scanner.ID,
		source.ID,
		"pkg:deb/debian/apt",
		"9.9.9",
		"MAL-APT-VERSIONS.json",
		multiVersionDetails,
	)

	svc := NewService(memStore, nil)

	if err := svc.processJob(context.Background(), componentVersioned); err != nil {
		t.Fatalf("process versioned component: %v", err)
	}
	findingsVersioned, err := memStore.ListComponentAnalysisFindings(componentVersioned)
	if err != nil {
		t.Fatalf("list findings versioned: %v", err)
	}
	assertFinding(t, findingsVersioned, "pkg:deb/debian/apt@2.6.1", store.ComponentAnalysisMatchExact)

	componentOutsideOSVList := "pkg:deb/debian/apt@9.9.9"
	if err := svc.processJob(context.Background(), componentOutsideOSVList); err != nil {
		t.Fatalf("process non-listed versioned component: %v", err)
	}
	findingsOutside, err := memStore.ListComponentAnalysisFindings(componentOutsideOSVList)
	if err != nil {
		t.Fatalf("list findings outside versions list: %v", err)
	}
	if len(findingsOutside) != 0 {
		t.Fatalf("expected no findings for %q, got %#v", componentOutsideOSVList, findingsOutside)
	}
}

func parseTrivyFixture(t *testing.T) *sbom.Document {
	t.Helper()
	root := repoRootWithSBOMs(t)
	path := filepath.Join(root, "sboms", "sbom_trivy_cyclonedx", "trivy_out_test_mal.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read trivy fixture: %v", err)
	}
	doc, err := sbom.Parse(payload)
	if err != nil {
		t.Fatalf("parse trivy fixture: %v", err)
	}
	return doc
}

func repoRootWithSBOMs(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for i := 0; i < 10; i++ {
		if info, err := os.Stat(filepath.Join(current, "sboms")); err == nil && info.IsDir() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	t.Fatalf("sboms directory not found from %s", wd)
	return ""
}

func findComponentPURL(t *testing.T, doc *sbom.Document, prefix string) string {
	t.Helper()
	wantPrefix := strings.TrimSpace(prefix)
	for _, component := range doc.Components {
		purl := strings.TrimSpace(component.PURL)
		if strings.HasPrefix(purl, wantPrefix) {
			return purl
		}
	}
	t.Fatalf("component purl prefix %q not found in fixture", wantPrefix)
	return ""
}

func insertFixtureMalwareFinding(
	t *testing.T,
	memStore store.Store,
	scannerID, sourceID uuid.UUID,
	componentPURL, detectVersion, filename string,
	detailsJSON json.RawMessage,
) {
	t.Helper()
	queue, err := memStore.UpsertAnalysisQueue(componentPURL, scannerID, store.AnalysisStatusProcessing)
	if err != nil {
		t.Fatalf("upsert analysis queue: %v", err)
	}
	if len(detailsJSON) == 0 {
		detailsJSON = json.RawMessage(`{"id":"MAL-FIXTURE"}`)
	}

	input := store.ScanComponentResultInput{
		ComponentPURL:  componentPURL,
		ScanID:         queue.ID,
		SourceID:       sourceID,
		ResultFilename: filename,
		Evidence:       "fixture malware",
		DetailsJSON:    detailsJSON,
		DetectVersion:  detectVersion,
		IsMalware:      true,
	}
	if _, err := memStore.UpsertScanComponentResult(input); err != nil {
		t.Fatalf("upsert scan component result: %v", err)
	}

	analysisResult, err := memStore.UpsertAnalysisResultFromFindings(componentPURL, "", "fixture malware")
	if err != nil {
		t.Fatalf("upsert analysis result from findings: %v", err)
	}
	input.AnalysisResultID = &analysisResult.ID
	if _, err := memStore.UpsertScanComponentResult(input); err != nil {
		t.Fatalf("link scan result to analysis result: %v", err)
	}
	if err := memStore.UpdateAnalysisQueueStatus(queue.ID, store.AnalysisStatusCompleted); err != nil {
		t.Fatalf("complete queue: %v", err)
	}
}

func assertFinding(t *testing.T, findings []models.ComponentAnalysisFinding, malwarePURL, matchType string) {
	t.Helper()
	for _, finding := range findings {
		if finding.MalwarePURL == malwarePURL && finding.MatchType == matchType {
			return
		}
	}
	t.Fatalf("expected finding malware_purl=%q match_type=%q, got=%v", malwarePURL, matchType, findings)
}
