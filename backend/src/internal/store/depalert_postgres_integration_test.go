package store_test

import (
	"testing"
	"time"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestGetDepAlertRevisionVerdict(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	productID := uuid.New()
	scopeID := uuid.New()
	testID := uuid.New()
	revisionID := uuid.New()
	sbomSHA := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	componentPURL := "pkg:npm/depalert-app@1.0.0"

	var projectID uuid.UUID
	if err := db.QueryRow(`
		SELECT id
		FROM projects
		WHERE LOWER(name) = LOWER('Default Project')
		LIMIT 1`).Scan(&projectID); err != nil {
		t.Fatalf("load default project: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO products (id, project_id, name, created_at, updated_at) VALUES ($1, $2, 'depalert-p', NOW(), NOW())`, productID, projectID); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scopes (id, product_id, name, created_at, updated_at) VALUES ($1, $2, 'depalert-s', NOW(), NOW())`, scopeID, productID); err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO tests (id, scope_id, name, sbom_standard, sbom_spec_version, created_at, updated_at)
		VALUES ($1, $2, 'depalert-t', 'cyclonedx', '1.6', NOW(), NOW())`, testID, scopeID); err != nil {
		t.Fatalf("insert test: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO sbom_objects (sha256, storage_path, size_bytes, format, content_type, is_gzip, created_at)
		VALUES ($1, 'ab/cd/dd', 1, 'cyclonedx', 'application/json', FALSE, NOW())`, sbomSHA); err != nil {
		t.Fatalf("insert sbom object: %v", err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO test_revisions (id, test_id, sbom_sha256, sbom_producer, is_active, components_count, last_modified_at, created_at)
		VALUES ($1, $2, $3, 'other', TRUE, 1, $4, $4)`, revisionID, testID, sbomSHA, now); err != nil {
		t.Fatalf("insert revision: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO components (revision_id, purl, pkg_name, version, pkg_type, sbom_type, created_at)
		VALUES ($1, $2, 'depalert-app', '1.0.0', 'library', 'cyclonedx', NOW())`, revisionID, componentPURL); err != nil {
		t.Fatalf("insert component: %v", err)
	}

	verdict, err := storeInstance.GetDepAlertRevisionVerdict(projectID, testID, revisionID)
	if err != nil {
		t.Fatalf("get depalert verdict (unknown): %v", err)
	}
	if verdict.Verdict != store.DepAlertVerdictUnknown {
		t.Fatalf("expected UNKNOWN verdict, got %s", verdict.Verdict)
	}
	if verdict.UnknownComponents != 1 || verdict.TotalComponents != 1 {
		t.Fatalf("expected unknown=1 total=1, got unknown=%d total=%d", verdict.UnknownComponents, verdict.TotalComponents)
	}

	scannedAt := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO component_analysis_malware_component_state (component_purl, scanned_at, valid_until, updated_at)
		VALUES ($1, $2, NULL, NOW())
		ON CONFLICT (component_purl) DO UPDATE SET scanned_at = EXCLUDED.scanned_at, valid_until = EXCLUDED.valid_until, updated_at = NOW()`,
		componentPURL, scannedAt); err != nil {
		t.Fatalf("insert component state: %v", err)
	}

	verdict, err = storeInstance.GetDepAlertRevisionVerdict(projectID, testID, revisionID)
	if err != nil {
		t.Fatalf("get depalert verdict (clean): %v", err)
	}
	if verdict.Verdict != store.DepAlertVerdictClean {
		t.Fatalf("expected CLEAN verdict, got %s", verdict.Verdict)
	}
	if verdict.CleanComponents != 1 || verdict.UnknownComponents != 0 {
		t.Fatalf("expected clean=1 unknown=0, got clean=%d unknown=%d", verdict.CleanComponents, verdict.UnknownComponents)
	}

	malwareResultID := uuid.New()
	malwarePURL := "pkg:npm/bad-package@9.9.9"
	if _, err := db.Exec(`
		INSERT INTO source_malware_input_results (id, component_purl, verdict, findings_count, scanned_at)
		VALUES ($1, $2, 'MALWARE', 1, NOW())`, malwareResultID, malwarePURL); err != nil {
		t.Fatalf("insert malware result: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO component_analysis_malware_findings (component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at)
		VALUES ($1, $2, $3, 'EXACT', NOW(), NOW())`, componentPURL, malwarePURL, malwareResultID); err != nil {
		t.Fatalf("insert malware finding: %v", err)
	}

	verdict, err = storeInstance.GetDepAlertRevisionVerdict(projectID, testID, revisionID)
	if err != nil {
		t.Fatalf("get depalert verdict (malware): %v", err)
	}
	if verdict.Verdict != store.DepAlertVerdictMalware {
		t.Fatalf("expected MALWARE verdict, got %s", verdict.Verdict)
	}
	if verdict.MalwareComponents != 1 || verdict.CleanComponents != 0 || verdict.UnknownComponents != 0 {
		t.Fatalf("expected malware=1 clean=0 unknown=0, got malware=%d clean=%d unknown=%d", verdict.MalwareComponents, verdict.CleanComponents, verdict.UnknownComponents)
	}
}
