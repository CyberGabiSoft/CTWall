package store_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestUpsertComponentAnalysisFinding_CreatesAlertForExistingMappingInActiveRevision(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-existing-mapping-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-existing-mapping-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-existing-mapping-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	sbomSHA := strings.Repeat("a", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb"
	revision, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision.ID); err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}

	malwarePURL := componentPURL
	resultID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert existing mapping: %v", err)
	}

	// Conflict-update path (mapping already exists globally): must still produce alert for current active context.
	if _, err := storeInstance.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
		ComponentPURL:              componentPURL,
		MalwarePURL:                malwarePURL,
		SourceMalwareInputResultID: resultID,
		MatchType:                  store.ComponentAnalysisMatchExact,
	}); err != nil {
		t.Fatalf("upsert finding (first): %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list alert groups: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected exactly one malware.detected group, total=%d len=%d", total, len(groups))
	}
	if groups[0].Status != "OPEN" {
		t.Fatalf("expected OPEN status, got %s", groups[0].Status)
	}

	groupID := groups[0].ID
	occ, occTotal, err := storeInstance.ListAlertOccurrences(store.AlertOccurrencesQuery{
		ProjectID: product.ProjectID,
		GroupID:   &groupID,
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list occurrences: %v", err)
	}
	if occTotal != 1 || len(occ) != 1 {
		t.Fatalf("expected one occurrence, total=%d len=%d", occTotal, len(occ))
	}

	var details map[string]any
	if err := json.Unmarshal(occ[0].Details, &details); err != nil {
		t.Fatalf("decode occurrence details: %v", err)
	}
	if details["malwarePurl"] != malwarePURL {
		t.Fatalf("unexpected malwarePurl in occurrence: %#v", details["malwarePurl"])
	}
	if details["componentPurl"] != componentPURL {
		t.Fatalf("unexpected componentPurl in occurrence: %#v", details["componentPurl"])
	}

	// Second update must be idempotent for the same OPEN context (no duplicate occurrences).
	if _, err := storeInstance.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
		ComponentPURL:              componentPURL,
		MalwarePURL:                malwarePURL,
		SourceMalwareInputResultID: resultID,
		MatchType:                  store.ComponentAnalysisMatchExact,
	}); err != nil {
		t.Fatalf("upsert finding (second): %v", err)
	}

	occ, occTotal, err = storeInstance.ListAlertOccurrences(store.AlertOccurrencesQuery{
		ProjectID: product.ProjectID,
		GroupID:   &groupID,
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list occurrences after second upsert: %v", err)
	}
	if occTotal != 1 || len(occ) != 1 {
		t.Fatalf("expected one occurrence after second upsert, total=%d len=%d", occTotal, len(occ))
	}
}

func TestAddRevision_CreatesMalwareAlertFromExistingMappingsWithoutQueueRun(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-ingest-backfill-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-ingest-backfill-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-ingest-backfill-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb"
	malwarePURL := componentPURL
	resultID := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert existing mapping: %v", err)
	}

	// Fresh analysis state means enqueue path can skip queue run; ingest must still create alert from existing mappings.
	if _, err := storeInstance.UpsertComponentAnalysisMalwareComponentState(componentPURL, nowUTC(), ptrTime(nowUTC().Add(24*time.Hour))); err != nil {
		t.Fatalf("upsert component state: %v", err)
	}

	sbomSHA := strings.Repeat("b", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision.ID); err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list alert groups: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected one malware.detected group after ingest, total=%d len=%d", total, len(groups))
	}
}

func TestUpsertComponentAnalysisFinding_DoesNotDuplicateWhenGroupAcknowledged(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-ack-dedup-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-ack-dedup-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-ack-dedup-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	sbomSHA := strings.Repeat("c", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb"
	if _, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	}); err != nil {
		t.Fatalf("add revision: %v", err)
	}

	malwarePURL := componentPURL
	resultID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := storeInstance.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
		ComponentPURL:              componentPURL,
		MalwarePURL:                malwarePURL,
		SourceMalwareInputResultID: resultID,
		MatchType:                  store.ComponentAnalysisMatchExact,
	}); err != nil {
		t.Fatalf("upsert finding: %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list alert groups: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected one malware.detected group, total=%d len=%d", total, len(groups))
	}
	groupID := groups[0].ID

	actor, err := storeInstance.CreateUser("alerts-ack-dedup@example.com", "hash", "ADMIN", "USER", "Ack User")
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	if err := storeInstance.AcknowledgeAlertGroup(product.ProjectID, groupID, actor.ID); err != nil {
		t.Fatalf("acknowledge alert group: %v", err)
	}

	// Same finding in same test after acknowledge: no duplicate occurrence expected.
	if _, err := storeInstance.UpsertComponentAnalysisFinding(store.ComponentAnalysisFindingInput{
		ComponentPURL:              componentPURL,
		MalwarePURL:                malwarePURL,
		SourceMalwareInputResultID: resultID,
		MatchType:                  store.ComponentAnalysisMatchExact,
	}); err != nil {
		t.Fatalf("upsert finding second time: %v", err)
	}

	occ, occTotal, err := storeInstance.ListAlertOccurrences(store.AlertOccurrencesQuery{
		ProjectID: product.ProjectID,
		GroupID:   &groupID,
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list occurrences: %v", err)
	}
	if occTotal != 1 || len(occ) != 1 {
		t.Fatalf("expected one occurrence for acknowledged dedup case, total=%d len=%d", occTotal, len(occ))
	}
}

func TestAddRevision_ReopensFixedTriageAndAlertForSameFinding(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-reopen-closed-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-reopen-closed-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-reopen-closed-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb"
	malwarePURL := componentPURL
	resultID := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}

	sbomSHA1 := strings.Repeat("d", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA1, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom1: %v", err)
	}
	revision1, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA1,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision 1: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision1.ID); err != nil {
		t.Fatalf("compute revision diff 1: %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups first: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected one group after first import, total=%d len=%d", total, len(groups))
	}
	if groups[0].Occurrences != 1 {
		t.Fatalf("expected 1 active occurrence after first import, got %d", groups[0].Occurrences)
	}
	groupID := groups[0].ID

	actor, err := storeInstance.CreateUser("alerts-reopen-closed@example.com", "hash", "ADMIN", "USER", "Reopen User")
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testItem.ID,
		componentPURL,
		malwarePURL,
		"FIXED",
		nil,
		nil,
		nil,
		&actor.ID,
	); err != nil {
		t.Fatalf("set triage FIXED: %v", err)
	}
	if err := storeInstance.CloseAlertGroup(product.ProjectID, groupID, actor.ID); err != nil {
		t.Fatalf("close alert group: %v", err)
	}

	groups, total, err = storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups closed: %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].Status != "CLOSED" {
		t.Fatalf("expected CLOSED group before reimport, total=%d len=%d status=%s", total, len(groups), groups[0].Status)
	}
	if groups[0].Occurrences != 0 {
		t.Fatalf("expected 0 active occurrences for CLOSED/FIXED state, got %d", groups[0].Occurrences)
	}

	sbomSHA2 := strings.Repeat("e", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA2, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom2: %v", err)
	}
	revision2, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA2,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.1",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision 2: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision2.ID); err != nil {
		t.Fatalf("compute revision diff 2: %v", err)
	}

	groups, total, err = storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups reopened: %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].Status != "OPEN" {
		t.Fatalf("expected OPEN group after reimport, total=%d len=%d status=%s", total, len(groups), groups[0].Status)
	}
	if groups[0].Occurrences != 1 {
		t.Fatalf("expected 1 active occurrence after reimport, got %d", groups[0].Occurrences)
	}

	findings, err := storeInstance.ListActiveTestComponentAnalysisMalwareFindings(testItem.ID, 50, 0)
	if err != nil {
		t.Fatalf("list findings after reimport: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings after reimport")
	}
	if findings[0].TriageStatus != "OPEN" {
		t.Fatalf("expected triage OPEN after reimport, got %s", findings[0].TriageStatus)
	}
	summary, err := storeInstance.GetActiveTestRevisionMalwareSummary(testItem.ID)
	if err != nil {
		t.Fatalf("get active malware summary after reimport: %v", err)
	}
	if summary.RevisionID != revision2.ID {
		t.Fatalf("expected summary for active revision %s, got %s", revision2.ID, summary.RevisionID)
	}
	if summary.MalwareComponentCount != 1 {
		t.Fatalf("expected malware summary count 1 after reimport reopen, got %d", summary.MalwareComponentCount)
	}

	occ, occTotal, err := storeInstance.ListAlertOccurrences(store.AlertOccurrencesQuery{
		ProjectID: product.ProjectID,
		GroupID:   &groupID,
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list occurrences reopened: %v", err)
	}
	if occTotal < 2 || len(occ) < 2 {
		t.Fatalf("expected at least two occurrences after reopen, total=%d len=%d", occTotal, len(occ))
	}
}

func TestAddRevision_ReopensFalsePositiveTriageAndAlertForSameFinding(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-reopen-false-positive-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-reopen-false-positive-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-reopen-false-positive-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb-fp"
	malwarePURL := componentPURL
	resultID := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}

	sbomSHA1 := strings.Repeat("h", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA1, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom1: %v", err)
	}
	revision1, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA1,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb-fp",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision 1: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision1.ID); err != nil {
		t.Fatalf("compute revision diff 1: %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups first: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected one group after first import, total=%d len=%d", total, len(groups))
	}
	groupID := groups[0].ID

	actor, err := storeInstance.CreateUser("alerts-reopen-false-positive@example.com", "hash", "ADMIN", "USER", "Reopen FP User")
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testItem.ID,
		componentPURL,
		malwarePURL,
		"FALSE_POSITIVE",
		nil,
		ptrString("manual false positive before reimport"),
		nil,
		&actor.ID,
	); err != nil {
		t.Fatalf("set triage FALSE_POSITIVE: %v", err)
	}
	if err := storeInstance.CloseAlertGroup(product.ProjectID, groupID, actor.ID); err != nil {
		t.Fatalf("close alert group: %v", err)
	}

	sbomSHA2 := strings.Repeat("i", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA2, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom2: %v", err)
	}
	revision2, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA2,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb-fp",
				Version:  "1.0.1",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision 2: %v", err)
	}
	diffSummary, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision2.ID)
	if err != nil {
		t.Fatalf("compute revision diff 2: %v", err)
	}
	if diffSummary.ReappearedCount != 1 {
		t.Fatalf("expected reappeared_count=1 for FALSE_POSITIVE reimport, got %+v", diffSummary)
	}

	groups, total, err = storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups reopened: %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].Status != "OPEN" {
		t.Fatalf("expected OPEN group after reimport from FALSE_POSITIVE, total=%d len=%d status=%s", total, len(groups), groups[0].Status)
	}
	if groups[0].Occurrences != 1 {
		t.Fatalf("expected 1 active occurrence after FALSE_POSITIVE reopen, got %d", groups[0].Occurrences)
	}

	findings, err := storeInstance.ListActiveTestComponentAnalysisMalwareFindings(testItem.ID, 50, 0)
	if err != nil {
		t.Fatalf("list findings after reimport: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings after reimport")
	}
	if findings[0].TriageStatus != "OPEN" {
		t.Fatalf("expected triage OPEN after FALSE_POSITIVE reimport, got %s", findings[0].TriageStatus)
	}
}

func TestCreateMalwareDetectedAlertOccurrences_RecomputesSummaryAfterAutoReopenFixed(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-auto-reopen-summary-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-auto-reopen-summary-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-auto-reopen-summary-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb-auto-reopen-summary"
	malwarePURL := componentPURL
	resultID := uuid.New()

	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert mapping: %v", err)
	}

	sbomSHA := strings.Repeat("j", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb-auto-reopen-summary",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision.ID); err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}

	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testItem.ID,
		componentPURL,
		malwarePURL,
		"FIXED",
		nil,
		nil,
		nil,
		nil,
	); err != nil {
		t.Fatalf("set triage FIXED: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionMalwareSummary(revision.ID); err != nil {
		t.Fatalf("recompute summary after FIXED: %v", err)
	}
	summary, err := storeInstance.GetActiveTestRevisionMalwareSummary(testItem.ID)
	if err != nil {
		t.Fatalf("load summary before reopen: %v", err)
	}
	if summary.MalwareComponentCount != 0 {
		t.Fatalf("expected summary count 0 after FIXED, got %d", summary.MalwareComponentCount)
	}

	if _, err := storeInstance.CreateMalwareDetectedAlertOccurrences(componentPURL, malwarePURL); err != nil {
		t.Fatalf("create malware alert occurrences: %v", err)
	}

	findings, err := storeInstance.ListActiveTestComponentAnalysisMalwareFindings(testItem.ID, 50, 0)
	if err != nil {
		t.Fatalf("list findings after auto reopen: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings after auto reopen")
	}
	if findings[0].TriageStatus != "OPEN" {
		t.Fatalf("expected triage OPEN after auto reopen, got %s", findings[0].TriageStatus)
	}

	summary, err = storeInstance.GetActiveTestRevisionMalwareSummary(testItem.ID)
	if err != nil {
		t.Fatalf("load summary after auto reopen: %v", err)
	}
	if summary.MalwareComponentCount != 1 {
		t.Fatalf("expected summary count 1 after auto reopen, got %d", summary.MalwareComponentCount)
	}
}

func TestListAlertGroups_AutoClosesOpenMalwareGroupWithZeroActiveOccurrences(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("alerts-autoclose-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "alerts-autoclose-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "alerts-autoclose-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentPURL := "pkg:pypi/tsplitlgtb"
	malwarePURL := componentPURL
	resultID := uuid.New()
	if _, err := db.Exec(
		`INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		 VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())`,
		resultID, malwarePURL,
	); err != nil {
		t.Fatalf("insert analysis result: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		 VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`,
		componentPURL, malwarePURL, resultID,
	); err != nil {
		t.Fatalf("insert finding mapping: %v", err)
	}

	sbomSHA := strings.Repeat("f", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{
				PURL:     componentPURL,
				PkgName:  "tsplitlgtb",
				Version:  "1.0.0",
				PkgType:  "pypi",
				SbomType: "library",
			},
		},
	})
	if err != nil {
		t.Fatalf("add revision: %v", err)
	}
	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(revision.ID); err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}

	groups, total, err := storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Status:    []store.AlertGroupStatus{store.AlertGroupStatusOpen},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list open groups before triage: %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].Status != "OPEN" {
		t.Fatalf("expected one OPEN group before triage, total=%d len=%d status=%s", total, len(groups), groups[0].Status)
	}

	actor, err := storeInstance.CreateUser("alerts-autoclose@example.com", "hash", "ADMIN", "USER", "Auto Close")
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testItem.ID,
		componentPURL,
		malwarePURL,
		"FIXED",
		nil,
		nil,
		nil,
		&actor.ID,
	); err != nil {
		t.Fatalf("set triage fixed: %v", err)
	}

	groups, total, err = storeInstance.ListAlertGroups(store.AlertGroupsQuery{
		ProjectID: product.ProjectID,
		Types:     []string{"malware.detected"},
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list groups after fixed triage: %v", err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("expected one malware group after triage update, total=%d len=%d", total, len(groups))
	}
	if groups[0].Status != "CLOSED" {
		t.Fatalf("expected CLOSED group after auto-close reconciliation, got %s", groups[0].Status)
	}
	if groups[0].Occurrences != 0 {
		t.Fatalf("expected zero active occurrences after fixed triage, got %d", groups[0].Occurrences)
	}
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
