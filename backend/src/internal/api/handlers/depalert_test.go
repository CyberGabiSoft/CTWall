package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"backend/internal/core/auth"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestGetDepAlertRevisionVerdictHandler(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	handler := GetDepAlertRevisionVerdictHandler(pgStore)

	adminID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, email, password_hash, role, account_type, full_name, created_at, updated_at)
		VALUES ($1, 'admin-depalert@ctwall.local', 'x', 'ADMIN', 'USER', 'Admin', NOW(), NOW())`, adminID); err != nil {
		t.Fatalf("insert admin user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tests/bad/revisions/bad/depalert-verdict", nil)
	req.SetPathValue("testId", "bad")
	req.SetPathValue("revisionId", "bad")
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: adminID, Role: auth.RoleAdmin}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	productID := uuid.New()
	scopeID := uuid.New()
	testID := uuid.New()
	revisionID := uuid.New()
	sbomSHA := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	componentPurl := "pkg:npm/depalert-handler@1.0.0"
	var projectID uuid.UUID
	if err := db.QueryRow(`
		SELECT id
		FROM projects
		WHERE LOWER(name) = LOWER('Default Project')
		LIMIT 1`).Scan(&projectID); err != nil {
		t.Fatalf("load default project: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO products (id, project_id, name, created_at, updated_at) VALUES ($1, $2, 'depalert-h-p', NOW(), NOW())`, productID, projectID); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO scopes (id, product_id, name, created_at, updated_at) VALUES ($1, $2, 'depalert-h-s', NOW(), NOW())`, scopeID, productID); err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO tests (id, scope_id, name, sbom_standard, sbom_spec_version, created_at, updated_at)
		VALUES ($1, $2, 'depalert-h-t', 'cyclonedx', '1.6', NOW(), NOW())`, testID, scopeID); err != nil {
		t.Fatalf("insert test: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO sbom_objects (sha256, storage_path, size_bytes, format, content_type, is_gzip, created_at)
		VALUES ($1, 'ab/cd/ee', 1, 'cyclonedx', 'application/json', FALSE, NOW())`, sbomSHA); err != nil {
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
		VALUES ($1, $2, 'depalert-handler', '1.0.0', 'library', 'cyclonedx', NOW())`, revisionID, componentPurl); err != nil {
		t.Fatalf("insert component: %v", err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/tests/"+testID.String()+"/revisions/"+revisionID.String()+"/depalert-verdict", nil)
	req.SetPathValue("testId", testID.String())
	req.SetPathValue("revisionId", revisionID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{ID: adminID, Role: auth.RoleAdmin}))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["verdict"] != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN verdict, got %v", payload["verdict"])
	}
	if payload["unknownComponents"] != float64(1) {
		t.Fatalf("expected unknownComponents=1, got %v", payload["unknownComponents"])
	}
}
