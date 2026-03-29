package store_test

import (
	"testing"
	"time"

	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestRecomputeAnalysisResultsForSource(t *testing.T) {
	storeInstance, db := tests.NewPostgresTestStore(t)

	source1 := uuid.New()
	source2 := uuid.New()
	scanner1 := uuid.New()
	scanner2 := uuid.New()

	if _, err := db.Exec(`
		INSERT INTO scan_malware_source (id, name, source_type, base_url, config_json, is_active, created_at)
		VALUES ($1, 's1', 'OSV_API', 'https://example.invalid', '{}'::jsonb, TRUE, NOW())`, source1); err != nil {
		t.Fatalf("insert source1: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO scan_malware_source (id, name, source_type, base_url, config_json, is_active, created_at)
		VALUES ($1, 's2', 'OSV_API', 'https://example.invalid', '{}'::jsonb, TRUE, NOW())`, source2); err != nil {
		t.Fatalf("insert source2: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO source_scanners (id, source_id, name, scanner_type, version, results_path, config_json, created_at)
		VALUES ($1, $2, 'scanner1', 'MALWARE', 'v1', 'data', '{}'::jsonb, NOW())`, scanner1, source1); err != nil {
		t.Fatalf("insert scanner1: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO source_scanners (id, source_id, name, scanner_type, version, results_path, config_json, created_at)
		VALUES ($1, $2, 'scanner2', 'MALWARE', 'v1', 'data', '{}'::jsonb, NOW())`, scanner2, source2); err != nil {
		t.Fatalf("insert scanner2: %v", err)
	}

	purlA := "pkg:npm/a@1.0.0"
	purlB := "pkg:npm/b@2.0.0"

	queueA1 := uuid.New()
	queueB1 := uuid.New()
	queueA2 := uuid.New()

	if _, err := db.Exec(`
		INSERT INTO source_malware_input_queue (id, component_purl, scanner_id, status, created_at)
		VALUES ($1, $2, $3, 'COMPLETED', NOW())`, queueA1, purlA, scanner1); err != nil {
		t.Fatalf("insert queueA1: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO source_malware_input_queue (id, component_purl, scanner_id, status, created_at)
		VALUES ($1, $2, $3, 'COMPLETED', NOW())`, queueB1, purlB, scanner1); err != nil {
		t.Fatalf("insert queueB1: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO source_malware_input_queue (id, component_purl, scanner_id, status, created_at)
		VALUES ($1, $2, $3, 'COMPLETED', NOW())`, queueA2, purlA, scanner2); err != nil {
		t.Fatalf("insert queueA2: %v", err)
	}

	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO source_malware_input_component_results (
			component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware, created_at
		) VALUES
			($1, 'hash-a', NULL, $2, $3, 'a.json', '', '{}'::jsonb, $4, NULL, 'v1', '', FALSE, NOW()),
			($5, 'hash-b', NULL, $6, $7, 'b.json', '', '{}'::jsonb, $4, NULL, 'v1', '', TRUE, NOW()),
			($1, NULL, NULL, $8, $9, 'a2.json', '', '{}'::jsonb, $4, NULL, 'v1', '', TRUE, NOW())
	`, purlA, queueA1, source1, now, purlB, queueB1, source1, queueA2, source2); err != nil {
		t.Fatalf("insert component results: %v", err)
	}

	affected, err := storeInstance.RecomputeAnalysisResultsForSource(source1)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if affected != 2 {
		t.Fatalf("expected affected=2, got %d", affected)
	}

	var aID uuid.UUID
	var aVerdict string
	var aFindings int
	if err := db.QueryRow(`SELECT id, verdict, findings_count FROM source_malware_input_results WHERE component_purl = $1`, purlA).Scan(&aID, &aVerdict, &aFindings); err != nil {
		t.Fatalf("select result A: %v", err)
	}
	if aVerdict != "MALWARE" {
		t.Fatalf("expected A verdict MALWARE, got %s", aVerdict)
	}
	if aFindings != 2 {
		t.Fatalf("expected A findings_count=2, got %d", aFindings)
	}

	var bID uuid.UUID
	var bVerdict string
	var bFindings int
	if err := db.QueryRow(`SELECT id, verdict, findings_count FROM source_malware_input_results WHERE component_purl = $1`, purlB).Scan(&bID, &bVerdict, &bFindings); err != nil {
		t.Fatalf("select result B: %v", err)
	}
	if bVerdict != "MALWARE" {
		t.Fatalf("expected B verdict MALWARE, got %s", bVerdict)
	}
	if bFindings != 1 {
		t.Fatalf("expected B findings_count=1, got %d", bFindings)
	}

	// Ensure analysis_result_id links are repaired for all raw rows for those PURLs.
	var linkedA1 uuid.UUID
	if err := db.QueryRow(`
		SELECT analysis_result_id FROM source_malware_input_component_results
		WHERE source_id = $1 AND component_purl = $2 AND result_filename = 'a.json'`, source1, purlA).Scan(&linkedA1); err != nil {
		t.Fatalf("select linked a.json: %v", err)
	}
	if linkedA1 != aID {
		t.Fatalf("expected a.json analysis_result_id to match summary id")
	}

	var linkedA2 uuid.UUID
	if err := db.QueryRow(`
		SELECT analysis_result_id FROM source_malware_input_component_results
		WHERE source_id = $1 AND component_purl = $2 AND result_filename = 'a2.json'`, source2, purlA).Scan(&linkedA2); err != nil {
		t.Fatalf("select linked a2.json: %v", err)
	}
	if linkedA2 != aID {
		t.Fatalf("expected a2.json analysis_result_id to match summary id")
	}

	var linkedB uuid.UUID
	if err := db.QueryRow(`
		SELECT analysis_result_id FROM source_malware_input_component_results
		WHERE source_id = $1 AND component_purl = $2 AND result_filename = 'b.json'`, source1, purlB).Scan(&linkedB); err != nil {
		t.Fatalf("select linked b.json: %v", err)
	}
	if linkedB != bID {
		t.Fatalf("expected b.json analysis_result_id to match summary id")
	}
}
