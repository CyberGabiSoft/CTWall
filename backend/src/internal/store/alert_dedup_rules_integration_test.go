package store_test

import (
	"strings"
	"testing"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestResolveAlertDedupRule_DefaultAndOverride(t *testing.T) {
	storeInstance, _ := tests.NewPostgresTestStore(t)

	productA, err := storeInstance.CreateProduct("dedup-rules-product-a", "")
	if err != nil {
		t.Fatalf("create product A: %v", err)
	}
	scopeA, err := storeInstance.CreateScope(productA.ID, "dedup-rules-scope-a", "")
	if err != nil {
		t.Fatalf("create scope A: %v", err)
	}
	testA, _, err := storeInstance.EnsureTest(scopeA.ID, "dedup-rules-test-a", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test A: %v", err)
	}

	productB, err := storeInstance.CreateProduct("dedup-rules-product-b", "")
	if err != nil {
		t.Fatalf("create product B: %v", err)
	}
	scopeB, err := storeInstance.CreateScope(productB.ID, "dedup-rules-scope-b", "")
	if err != nil {
		t.Fatalf("create scope B: %v", err)
	}
	testB, _, err := storeInstance.EnsureTest(scopeB.ID, "dedup-rules-test-b", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test B: %v", err)
	}

	defRule, err := storeInstance.ResolveAlertDedupRule(store.AlertDedupRuleResolutionInput{
		ProjectID: productA.ProjectID,
		AlertType: "malware.detected",
		ProductID: &productA.ID,
		ScopeID:   &scopeA.ID,
		TestID:    &testA.ID,
	})
	if err != nil {
		t.Fatalf("resolve default rule: %v", err)
	}
	if defRule.DedupScope != string(store.AlertDedupScopeTest) {
		t.Fatalf("expected implicit TEST rule for malware, got %s", defRule.DedupScope)
	}

	_, err = storeInstance.ReplaceAlertDedupRules(productA.ProjectID, "malware.detected", []store.AlertDedupRuleInput{
		{
			AlertType:  "malware.detected",
			DedupScope: store.AlertDedupScopeProduct,
			ProductID:  &productA.ID,
			Enabled:    true,
		},
	})
	if err != nil {
		t.Fatalf("replace dedup rules: %v", err)
	}

	ruleA, err := storeInstance.ResolveAlertDedupRule(store.AlertDedupRuleResolutionInput{
		ProjectID: productA.ProjectID,
		AlertType: "malware.detected",
		ProductID: &productA.ID,
		ScopeID:   &scopeA.ID,
		TestID:    &testA.ID,
	})
	if err != nil {
		t.Fatalf("resolve product override: %v", err)
	}
	if ruleA.DedupScope != string(store.AlertDedupScopeProduct) {
		t.Fatalf("expected PRODUCT dedup scope for product A, got %s", ruleA.DedupScope)
	}

	ruleB, err := storeInstance.ResolveAlertDedupRule(store.AlertDedupRuleResolutionInput{
		ProjectID: productA.ProjectID,
		AlertType: "malware.detected",
		ProductID: &productB.ID,
		ScopeID:   &scopeB.ID,
		TestID:    &testB.ID,
	})
	if err != nil {
		t.Fatalf("resolve fallback global for product B: %v", err)
	}
	if ruleB.DedupScope != string(store.AlertDedupScopeTest) {
		t.Fatalf("expected TEST fallback for product B malware context, got %s", ruleB.DedupScope)
	}
}

func TestCreateMalwareDetectedAlertOccurrences_UsesTestDedupRule(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("dedup-occ-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "dedup-occ-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testA, _, err := storeInstance.EnsureTest(scope.ID, "dedup-occ-test-a", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test A: %v", err)
	}
	testB, _, err := storeInstance.EnsureTest(scope.ID, "dedup-occ-test-b", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test B: %v", err)
	}

	componentPURL := "pkg:pypi/dedup-malware"
	sbomA := strings.Repeat("d", 64)
	sbomB := strings.Repeat("e", 64)
	if _, err := storeInstance.StoreSbom(sbomA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom A: %v", err)
	}
	if _, err := storeInstance.StoreSbom(sbomB, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom B: %v", err)
	}
	if _, err := storeInstance.AddRevision(testA.ID, store.RevisionInput{
		SbomSha256:   sbomA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{{
			PURL:     componentPURL,
			PkgName:  "dedup-malware",
			Version:  "1.0.0",
			PkgType:  "pypi",
			SbomType: "library",
		}},
	}); err != nil {
		t.Fatalf("add revision test A: %v", err)
	}
	if _, err := storeInstance.AddRevision(testB.ID, store.RevisionInput{
		SbomSha256:   sbomB,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{{
			PURL:     componentPURL,
			PkgName:  "dedup-malware",
			Version:  "1.0.0",
			PkgType:  "pypi",
			SbomType: "library",
		}},
	}); err != nil {
		t.Fatalf("add revision test B: %v", err)
	}

	resultID := uuid.New()
	malwarePURL := componentPURL
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
		t.Fatalf("insert malware finding map: %v", err)
	}

	if _, err := storeInstance.ReplaceAlertDedupRules(product.ProjectID, "malware.detected", []store.AlertDedupRuleInput{
		{
			AlertType:  "malware.detected",
			DedupScope: store.AlertDedupScopeTest,
			TestID:     &testA.ID,
			Enabled:    true,
		},
		{
			AlertType:  "malware.detected",
			DedupScope: store.AlertDedupScopeTest,
			TestID:     &testB.ID,
			Enabled:    true,
		},
	}); err != nil {
		t.Fatalf("replace dedup rules: %v", err)
	}

	created, err := storeInstance.CreateMalwareDetectedAlertOccurrences(componentPURL, malwarePURL)
	if err != nil {
		t.Fatalf("create malware alert occurrences: %v", err)
	}
	if created != 2 {
		t.Fatalf("expected 2 created occurrences, got %d", created)
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
	if total != 2 || len(groups) != 2 {
		t.Fatalf("expected 2 malware groups for TEST dedup, total=%d len=%d", total, len(groups))
	}

	testScoped := 0
	for _, group := range groups {
		if strings.Contains(group.GroupKey, "dedup_on:test") {
			testScoped++
		}
	}
	if testScoped != 2 {
		t.Fatalf("expected both group keys to be test-scoped, got %d", testScoped)
	}
}

func TestCreateMalwareDetectedAlertOccurrences_DoesNotReopenFixedInOtherTests(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("dedup-fixed-other-test-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "dedup-fixed-other-test-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testA, _, err := storeInstance.EnsureTest(scope.ID, "dedup-fixed-other-test-a", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test A: %v", err)
	}
	testB, _, err := storeInstance.EnsureTest(scope.ID, "dedup-fixed-other-test-b", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test B: %v", err)
	}

	componentPURL := "pkg:pypi/dedup-fixed-other-test-malware"
	sbomA := strings.Repeat("f", 64)
	sbomB := strings.Repeat("g", 64)
	if _, err := storeInstance.StoreSbom(sbomA, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom A: %v", err)
	}
	if _, err := storeInstance.StoreSbom(sbomB, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom B: %v", err)
	}
	if _, err := storeInstance.AddRevision(testA.ID, store.RevisionInput{
		SbomSha256:   sbomA,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{{
			PURL:     componentPURL,
			PkgName:  "dedup-fixed-other-test-malware",
			Version:  "1.0.0",
			PkgType:  "pypi",
			SbomType: "library",
		}},
	}); err != nil {
		t.Fatalf("add revision test A: %v", err)
	}
	if _, err := storeInstance.AddRevision(testB.ID, store.RevisionInput{
		SbomSha256:   sbomB,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{{
			PURL:     componentPURL,
			PkgName:  "dedup-fixed-other-test-malware",
			Version:  "1.0.0",
			PkgType:  "pypi",
			SbomType: "library",
		}},
	}); err != nil {
		t.Fatalf("add revision test B: %v", err)
	}

	resultID := uuid.New()
	malwarePURL := componentPURL
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
		t.Fatalf("insert malware finding map: %v", err)
	}

	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testA.ID,
		componentPURL,
		malwarePURL,
		string(store.MalwareFindingTriageStatusOpen),
		nil,
		nil,
		nil,
		nil,
	); err != nil {
		t.Fatalf("set triage OPEN for test A: %v", err)
	}
	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testB.ID,
		componentPURL,
		malwarePURL,
		string(store.MalwareFindingTriageStatusFixed),
		nil,
		nil,
		nil,
		nil,
	); err != nil {
		t.Fatalf("set triage FIXED for test B: %v", err)
	}

	created, err := storeInstance.CreateMalwareDetectedAlertOccurrences(componentPURL, malwarePURL)
	if err != nil {
		t.Fatalf("create malware alert occurrences: %v", err)
	}
	if created != 1 {
		t.Fatalf("expected 1 created occurrence (only OPEN triage test), got %d", created)
	}

	var statusB string
	if err := db.QueryRow(
		`SELECT status
		   FROM component_malware_findings_triage
		  WHERE project_id = $1 AND test_id = $2 AND component_purl = $3 AND malware_purl = $4`,
		product.ProjectID, testB.ID, componentPURL, malwarePURL,
	).Scan(&statusB); err != nil {
		t.Fatalf("load triage status for test B: %v", err)
	}
	if statusB != string(store.MalwareFindingTriageStatusFixed) {
		t.Fatalf("expected triage for test B to remain FIXED, got %s", statusB)
	}

	var countA, countB int
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM alert_occurrences WHERE test_id = $1 AND entity_ref = $2 AND COALESCE(details->>'malwarePurl','') = $3`,
		testA.ID, componentPURL, malwarePURL,
	).Scan(&countA); err != nil {
		t.Fatalf("count occurrences for test A: %v", err)
	}
	if err := db.QueryRow(
		`SELECT COUNT(1) FROM alert_occurrences WHERE test_id = $1 AND entity_ref = $2 AND COALESCE(details->>'malwarePurl','') = $3`,
		testB.ID, componentPURL, malwarePURL,
	).Scan(&countB); err != nil {
		t.Fatalf("count occurrences for test B: %v", err)
	}
	if countA != 1 {
		t.Fatalf("expected exactly one occurrence for test A, got %d", countA)
	}
	if countB != 0 {
		t.Fatalf("expected zero occurrences for test B, got %d", countB)
	}
}
