package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

type dataGraphFixture struct {
	ProjectID     uuid.UUID
	TestID        uuid.UUID
	RevisionID    uuid.UUID
	ComponentPURL string
}

func seedDataGraphFixture(t *testing.T, st store.Store) dataGraphFixture {
	t.Helper()

	project, err := st.CreateProject("Graph Project", "Data Graph test project", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	product, err := st.CreateProductInProject(project.ID, "Graph Product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := st.CreateScope(product.ID, "Graph Scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testEntity, _, err := st.EnsureTest(scope.ID, "Graph Test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	sbomJSON := []byte(`{
  "bomFormat":"CycloneDX",
  "specVersion":"1.6",
  "metadata":{
    "timestamp":"2026-02-25T12:00:00Z",
    "tools":[{"name":"syft"}]
  },
  "components":[
    {"type":"library","bom-ref":"pkg:npm/acme-app@1.0.0","name":"acme-app","version":"1.0.0","purl":"pkg:npm/acme-app@1.0.0"},
    {"type":"library","bom-ref":"pkg:npm/acme-lib@2.0.0","name":"acme-lib","version":"2.0.0","purl":"pkg:npm/acme-lib@2.0.0"}
  ],
  "dependencies":[
    {"ref":"pkg:npm/acme-app@1.0.0","dependsOn":["pkg:npm/acme-lib@2.0.0"]}
  ]
}`)
	sbomSHA := strings.Repeat("a", 63) + "1"
	if _, err := st.StoreSbom(sbomSHA, sbomJSON, "cyclonedx-json@1.6", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}

	revision, err := st.AddRevision(testEntity.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "syft",
		Components: []store.ComponentInput{
			{
				PURL:     "pkg:npm/acme-app@1.0.0",
				PkgName:  "acme-app",
				Version:  "1.0.0",
				PkgType:  "npm",
				SbomType: "library",
			},
			{
				PURL:     "pkg:npm/acme-lib@2.0.0",
				PkgName:  "acme-lib",
				Version:  "2.0.0",
				PkgType:  "npm",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}

	result, err := st.CreateAnalysisResult(store.AnalysisResultInput{
		ComponentPURL: "pkg:npm/acme-app@1.0.0",
		Verdict:       "MALWARE",
		FindingsCount: 1,
		Summary:       "malware mapping found",
	})
	if err != nil {
		t.Fatalf("create analysis result: %v", err)
	}
	if _, err := st.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
		ComponentPURL:              "pkg:npm/acme-app@1.0.0",
		MalwarePURL:                "pkg:generic/fake-malware@9.9.9",
		SourceMalwareInputResultID: result.ID,
		MatchType:                  store.ComponentAnalysisMatchExact,
	}); err != nil {
		t.Fatalf("upsert component analysis finding: %v", err)
	}

	if _, err := st.EnqueueComponentAnalysis("pkg:npm/acme-app@1.0.0", store.ComponentAnalysisReasonManual, nil); err != nil {
		t.Fatalf("enqueue component analysis queue item: %v", err)
	}

	source, err := st.CreateScanMalwareSource("Graph Source", "OSV_API", "https://api.osv.dev", nil, true)
	if err != nil {
		t.Fatalf("create malware source: %v", err)
	}
	scanner, err := st.CreateScanner(source.ID, "Graph Scanner", "MALWARE", "v1", "", nil)
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	scanQueueItem, err := st.EnqueueAnalysis("pkg:npm/acme-app@1.0.0", scanner.ID)
	if err != nil {
		t.Fatalf("enqueue analysis queue item: %v", err)
	}
	if _, err := st.CreateScanComponentResult(store.ScanComponentResultInput{
		ComponentPURL: "pkg:npm/acme-app@1.0.0",
		ScanID:        scanQueueItem.ID,
		SourceID:      source.ID,
		DetailsJSON:   json.RawMessage(`{"reason":"unit-test"}`),
		IsMalware:     true,
	}); err != nil {
		t.Fatalf("create scan component result: %v", err)
	}

	return dataGraphFixture{
		ProjectID:     project.ID,
		TestID:        testEntity.ID,
		RevisionID:    revision.ID,
		ComponentPURL: "pkg:npm/acme-app@1.0.0",
	}
}

func TestDataGraphChainHandlerUnauthorized(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/graph/chain", nil)
	rec := httptest.NewRecorder()
	DataGraphChainHandler(pgStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestDataGraphChainHandlerInvalidTestID(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/graph/chain?testId=bad", nil)
	rec := httptest.NewRecorder()
	DataGraphChainHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDataGraphChainHandlerSuccess(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	fixture := seedDataGraphFixture(t, pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/graph/chain?testId="+fixture.TestID.String()+"&maxNodes=10", nil)
	req.Header.Set(projectHeaderName, fixture.ProjectID.String())
	rec := httptest.NewRecorder()
	DataGraphChainHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data struct {
			Nodes []struct {
				PURL      string `json:"purl"`
				IsMalware bool   `json:"isMalware"`
			} `json:"nodes"`
			Edges []struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"edges"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Data.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(payload.Data.Nodes))
	}
	if len(payload.Data.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(payload.Data.Edges))
	}
	var malwareMarked bool
	for _, node := range payload.Data.Nodes {
		if node.PURL == fixture.ComponentPURL && node.IsMalware {
			malwareMarked = true
		}
	}
	if !malwareMarked {
		t.Fatalf("expected malware node to be marked")
	}
}

func TestDataGraphComponentDetailsHandlerSuccess(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	fixture := seedDataGraphFixture(t, pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/graph/component-details?testId="+fixture.TestID.String()+"&purl="+fixture.ComponentPURL, nil)
	req.Header.Set(projectHeaderName, fixture.ProjectID.String())
	rec := httptest.NewRecorder()
	DataGraphComponentDetailsHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Data struct {
			Identity struct {
				PURL string `json:"purl"`
			} `json:"identity"`
			MalwareSummary struct {
				Verdict string `json:"verdict"`
			} `json:"malwareSummary"`
			MalwareFindings []json.RawMessage `json:"malwareFindings"`
			RawFindings     []json.RawMessage `json:"rawFindings"`
			QueueHistory    []json.RawMessage `json:"queueHistory"`
			Occurrences     []json.RawMessage `json:"occurrences"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.Identity.PURL != fixture.ComponentPURL {
		t.Fatalf("expected identity purl %q, got %q", fixture.ComponentPURL, payload.Data.Identity.PURL)
	}
	if payload.Data.MalwareSummary.Verdict != "MALWARE" {
		t.Fatalf("expected MALWARE verdict, got %q", payload.Data.MalwareSummary.Verdict)
	}
	if len(payload.Data.MalwareFindings) == 0 {
		t.Fatalf("expected malware findings")
	}
	if len(payload.Data.RawFindings) == 0 {
		t.Fatalf("expected raw findings")
	}
	if len(payload.Data.QueueHistory) == 0 {
		t.Fatalf("expected queue history")
	}
	if len(payload.Data.Occurrences) == 0 {
		t.Fatalf("expected occurrences")
	}
}
