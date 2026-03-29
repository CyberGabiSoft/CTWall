package store_test

import (
	"database/sql"
	"strings"
	"testing"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestComputeAndStoreTestRevisionFindingDiff_ReimportDeltaLifecycle(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("reimport-diff-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "reimport-diff-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "reimport-diff-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentA := "pkg:pypi/reimport-a@1.0.0"
	componentB := "pkg:pypi/reimport-b@1.0.0"
	componentC := "pkg:pypi/reimport-c@1.0.0"

	if err := insertMalwareMapping(t, db, componentA, componentA); err != nil {
		t.Fatalf("insert malware mapping a: %v", err)
	}
	if err := insertMalwareMapping(t, db, componentB, componentB); err != nil {
		t.Fatalf("insert malware mapping b: %v", err)
	}
	if err := insertMalwareMapping(t, db, componentC, componentC); err != nil {
		t.Fatalf("insert malware mapping c: %v", err)
	}

	sbomSHA1 := strings.Repeat("1", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA1, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom1: %v", err)
	}
	rev1, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA1,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{PURL: componentA, PkgName: "a", Version: "1.0.0", PkgType: "pypi", SbomType: "library"},
			{PURL: componentB, PkgName: "b", Version: "1.0.0", PkgType: "pypi", SbomType: "library"},
		},
	})
	if err != nil {
		t.Fatalf("add revision 1: %v", err)
	}

	// Fixed triage before reimport means the next ADDED for this key becomes REAPPEARED.
	if _, err := storeInstance.UpsertComponentMalwareFindingTriage(
		product.ProjectID,
		testItem.ID,
		componentC,
		componentC,
		"FIXED",
		nil,
		ptrString("manual fix before reimport"),
		nil,
		nil,
	); err != nil {
		t.Fatalf("seed fixed triage: %v", err)
	}

	sbomSHA2 := strings.Repeat("2", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA2, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom2: %v", err)
	}
	rev2, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA2,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{PURL: componentB, PkgName: "b", Version: "1.0.0", PkgType: "pypi", SbomType: "library"},
			{PURL: componentC, PkgName: "c", Version: "1.0.0", PkgType: "pypi", SbomType: "library"},
		},
	})
	if err != nil {
		t.Fatalf("add revision 2: %v", err)
	}

	summary, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(rev2.ID)
	if err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}
	if summary.ToRevisionID != rev2.ID {
		t.Fatalf("unexpected summary revision id: %s", summary.ToRevisionID)
	}
	if summary.FromRevisionID == nil || *summary.FromRevisionID != rev1.ID {
		t.Fatalf("expected from revision %s, got %#v", rev1.ID, summary.FromRevisionID)
	}
	if summary.AddedCount != 0 || summary.RemovedCount != 1 || summary.UnchangedCount != 1 || summary.ReappearedCount != 1 {
		t.Fatalf("unexpected summary counts: %+v", summary)
	}
	if summary.Status != store.TestRevisionFindingDiffStatusCompleted {
		t.Fatalf("expected completed summary status, got %s", summary.Status)
	}

	diffs, err := storeInstance.ListTestRevisionFindingDiffs(testItem.ID, rev2.ID, nil)
	if err != nil {
		t.Fatalf("list revision diffs: %v", err)
	}
	if len(diffs) != 3 {
		t.Fatalf("expected 3 diff rows, got %d", len(diffs))
	}

	diffByKey := map[string]string{}
	for _, item := range diffs {
		diffByKey[item.ComponentPURL+"|"+item.MalwarePURL] = item.DiffType
	}
	if diffByKey[componentA+"|"+componentA] != store.TestRevisionFindingDiffTypeRemoved {
		t.Fatalf("expected REMOVED for componentA, got %q", diffByKey[componentA+"|"+componentA])
	}
	if diffByKey[componentB+"|"+componentB] != store.TestRevisionFindingDiffTypeUnchanged {
		t.Fatalf("expected UNCHANGED for componentB, got %q", diffByKey[componentB+"|"+componentB])
	}
	if diffByKey[componentC+"|"+componentC] != store.TestRevisionFindingDiffTypeReappeared {
		t.Fatalf("expected REAPPEARED for componentC, got %q", diffByKey[componentC+"|"+componentC])
	}

	// REMOVED finding is auto-fixed by technical system user and reason describes the cause.
	var removedStatus string
	var removedReason string
	var removedAuthorEmail string
	if err := db.QueryRow(`
SELECT tri.status, COALESCE(tri.reason, ''), COALESCE(u.email, '')
FROM component_malware_findings_triage tri
LEFT JOIN users u ON u.id = tri.author_id
WHERE tri.project_id = $1
  AND tri.test_id = $2
  AND tri.component_purl = $3
  AND tri.malware_purl = $4
`, product.ProjectID, testItem.ID, componentA, componentA).Scan(&removedStatus, &removedReason, &removedAuthorEmail); err != nil {
		t.Fatalf("query auto-fixed triage: %v", err)
	}
	if removedStatus != "FIXED" {
		t.Fatalf("expected FIXED triage for removed finding, got %s", removedStatus)
	}
	if removedReason != "Finding removed after SBOM reimport." {
		t.Fatalf("unexpected auto-close reason: %q", removedReason)
	}
	if removedAuthorEmail != "system@ctwall.local" {
		t.Fatalf("expected system actor, got %q", removedAuthorEmail)
	}
	var systemPasswordHash string
	if err := db.QueryRow(`
SELECT password_hash
FROM users
WHERE LOWER(email) = LOWER($1)
LIMIT 1
`, "system@ctwall.local").Scan(&systemPasswordHash); err != nil {
		t.Fatalf("query system actor hash: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(systemPasswordHash), "$argon2id$") {
		t.Fatalf("expected argon2id hash for system actor, got %q", systemPasswordHash)
	}

	// REAPPEARED finding should be re-opened.
	var reappearedStatus string
	if err := db.QueryRow(`
SELECT status
FROM component_malware_findings_triage
WHERE project_id = $1
  AND test_id = $2
  AND component_purl = $3
  AND malware_purl = $4
`, product.ProjectID, testItem.ID, componentC, componentC).Scan(&reappearedStatus); err != nil {
		t.Fatalf("query reappeared triage status: %v", err)
	}
	if reappearedStatus != "OPEN" {
		t.Fatalf("expected OPEN triage for reappeared finding, got %s", reappearedStatus)
	}
}

func TestComputeAndStoreTestRevisionFindingDiff_MigratesLegacySystemActorPasswordHash(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	product, err := storeInstance.CreateProduct("reimport-legacy-system-actor-product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := storeInstance.CreateScope(product.ID, "reimport-legacy-system-actor-scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testItem, _, err := storeInstance.EnsureTest(scope.ID, "reimport-legacy-system-actor-test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("ensure test: %v", err)
	}

	componentA := "pkg:pypi/reimport-legacy-system-actor-a@1.0.0"
	if err := insertMalwareMapping(t, db, componentA, componentA); err != nil {
		t.Fatalf("insert malware mapping a: %v", err)
	}

	var legacyActorID uuid.UUID
	if err := db.QueryRow(`
INSERT INTO users (email, password_hash, role, account_type, full_name, created_at, updated_at)
VALUES ($1, $2, 'NONE', 'SERVICE_ACCOUNT', 'system', NOW(), NOW())
RETURNING id
`, "system@ctwall.local", "system-disabled-login").Scan(&legacyActorID); err != nil {
		t.Fatalf("insert legacy system actor: %v", err)
	}

	sbomSHA1 := strings.Repeat("a", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA1, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom1: %v", err)
	}
	if _, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA1,
		SbomProducer: "trivy",
		Components: []store.ComponentInput{
			{PURL: componentA, PkgName: "a", Version: "1.0.0", PkgType: "pypi", SbomType: "library"},
		},
	}); err != nil {
		t.Fatalf("add revision 1: %v", err)
	}

	sbomSHA2 := strings.Repeat("b", 64)
	if _, err := storeInstance.StoreSbom(sbomSHA2, []byte(`{"bomFormat":"CycloneDX"}`), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom2: %v", err)
	}
	rev2, err := storeInstance.AddRevision(testItem.ID, store.RevisionInput{
		SbomSha256:   sbomSHA2,
		SbomProducer: "trivy",
		Components:   []store.ComponentInput{},
	})
	if err != nil {
		t.Fatalf("add revision 2: %v", err)
	}

	if _, err := storeInstance.ComputeAndStoreTestRevisionFindingDiff(rev2.ID); err != nil {
		t.Fatalf("compute revision diff: %v", err)
	}

	var actorID uuid.UUID
	var actorPasswordHash string
	if err := db.QueryRow(`
SELECT id, password_hash
FROM users
WHERE LOWER(email) = LOWER($1)
LIMIT 1
`, "system@ctwall.local").Scan(&actorID, &actorPasswordHash); err != nil {
		t.Fatalf("query system actor after diff compute: %v", err)
	}
	if actorID != legacyActorID {
		t.Fatalf("expected existing system actor id to be reused")
	}
	if !strings.HasPrefix(strings.TrimSpace(actorPasswordHash), "$argon2id$") {
		t.Fatalf("expected argon2id hash, got %q", actorPasswordHash)
	}
	if actorPasswordHash == "system-disabled-login" {
		t.Fatalf("legacy plaintext-like value should be replaced")
	}
}

func insertMalwareMapping(t *testing.T, db *sql.DB, componentPURL, malwarePURL string) error {
	t.Helper()
	resultID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, summary, scanned_at)
		VALUES ($1, $2, 'MALWARE', 1, 'malware', NOW())
	`, resultID, malwarePURL); err != nil {
		return err
	}
	if _, err := db.Exec(`
		INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())
	`, componentPURL, malwarePURL, resultID); err != nil {
		return err
	}
	return nil
}

func ptrString(value string) *string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	return &v
}
