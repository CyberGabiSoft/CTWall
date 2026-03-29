package store

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCreateScanMalwareSource(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.CreateScanMalwareSource(" ", "OSV_API", "https://api.osv.dev", nil, true); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	insert := `INSERT INTO scan_malware_source (name, source_type, base_url, config_json, is_active)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, name, source_type, base_url, config_json, is_active, created_at`
	expectQuery(mock, insert).
		WithArgs("OSV", "OSV_API", "https://api.osv.dev", sqlmock.AnyArg(), true).
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateScanMalwareSource("OSV", "OSV_API", "https://api.osv.dev", nil, true); err == nil {
		t.Fatalf("expected insert error")
	}

	now := time.Now()
	sourceID := uuid.New()
	expectQuery(mock, insert).
		WithArgs("OSV", "OSV_API", "https://api.osv.dev", sqlmock.AnyArg(), true).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "source_type", "base_url", "config_json", "is_active", "created_at"}).
			AddRow(sourceID, "OSV", "OSV_API", "https://api.osv.dev", []byte(`{}`), true, now))
	source, err := store.CreateScanMalwareSource("OSV", "OSV_API", "https://api.osv.dev", nil, true)
	if err != nil || source.ID != sourceID {
		t.Fatalf("expected source success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestListScanMalwareSources(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	query := `SELECT id, name, source_type, base_url, config_json, is_active, created_at
		 FROM scan_malware_source
		 ORDER BY name`
	expectQuery(mock, query).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListScanMalwareSources(); err == nil {
		t.Fatalf("expected query error")
	}

	expectQuery(mock, query).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "source_type", "base_url", "config_json", "is_active", "created_at"}).
			AddRow("bad", "OSV", "OSV_API", "https://api.osv.dev", []byte(`{}`), true, time.Now()))
	if _, err := store.ListScanMalwareSources(); err == nil {
		t.Fatalf("expected scan error")
	}

	sourceID := uuid.New()
	expectQuery(mock, query).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "source_type", "base_url", "config_json", "is_active", "created_at"}).
			AddRow(sourceID, "OSV", "OSV_API", "https://api.osv.dev", []byte(`{}`), true, time.Now()))
	if sources, err := store.ListScanMalwareSources(); err != nil || len(sources) != 1 {
		t.Fatalf("expected sources list")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestCreateScanner(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.CreateScanner(uuid.New(), " ", "MALWARE", "v1", "data/osv", nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	sourceID := uuid.New()
	exists := `SELECT EXISTS(SELECT 1 FROM scan_malware_source WHERE id = $1)`
	expectQuery(mock, exists).
		WithArgs(sourceID).
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateScanner(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", nil); err == nil {
		t.Fatalf("expected source exists error")
	}

	expectQuery(mock, exists).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, err := store.CreateScanner(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected source not found")
	}

	insert := `INSERT INTO source_scanners (source_id, name, scanner_type, version, results_path, config_json)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, source_id, name, scanner_type, version, results_path, config_json, created_at`
	expectQuery(mock, exists).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, insert).
		WithArgs(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", sqlmock.AnyArg()).
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateScanner(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", nil); err == nil {
		t.Fatalf("expected insert error")
	}

	scannerID := uuid.New()
	expectQuery(mock, exists).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, insert).
		WithArgs(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_id", "name", "scanner_type", "version", "results_path", "config_json", "created_at"}).
			AddRow(scannerID, sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", []byte(`{}`), time.Now()))
	scanner, err := store.CreateScanner(sourceID, "OSV Scanner", "MALWARE", "v1", "data/osv", nil)
	if err != nil || scanner.ID != scannerID {
		t.Fatalf("expected scanner success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestListScanners(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	query := `SELECT id, source_id, name, scanner_type, version, results_path, config_json, created_at
		 FROM source_scanners
		 ORDER BY name`
	expectQuery(mock, query).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListScanners(); err == nil {
		t.Fatalf("expected query error")
	}

	expectQuery(mock, query).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_id", "name", "scanner_type", "version", "results_path", "config_json", "created_at"}).
			AddRow("bad", uuid.New(), "OSV Scanner", "MALWARE", "v1", "data/osv", []byte(`{}`), time.Now()))
	if _, err := store.ListScanners(); err == nil {
		t.Fatalf("expected scan error")
	}

	expectQuery(mock, query).
		WillReturnRows(sqlmock.NewRows([]string{"id", "source_id", "name", "scanner_type", "version", "results_path", "config_json", "created_at"}).
			AddRow(uuid.New(), uuid.New(), "OSV Scanner", "MALWARE", "v1", "data/osv", []byte(`{}`), time.Now()))
	if source_scanners, err := store.ListScanners(); err != nil || len(source_scanners) != 1 {
		t.Fatalf("expected source_scanners list")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestEnqueueAnalysis(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.EnqueueAnalysis(" ", uuid.New()); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	scanID := uuid.New()
	exists := `SELECT EXISTS(SELECT 1 FROM source_scanners WHERE id = $1)`
	expectQuery(mock, exists).
		WithArgs(scanID).
		WillReturnError(errors.New("boom"))
	if _, err := store.EnqueueAnalysis("pkg:npm/leftpad@1.0.0", scanID); err == nil {
		t.Fatalf("expected scanner exists error")
	}

	expectQuery(mock, exists).
		WithArgs(scanID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, err := store.EnqueueAnalysis("pkg:npm/leftpad@1.0.0", scanID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}

	insert := `INSERT INTO source_malware_input_queue (component_purl, scanner_id, status)
		 VALUES ($1, $2, $3)
		 RETURNING id, component_purl, scanner_id, status, created_at`
	lookup := `SELECT id, status
		 FROM source_malware_input_queue
		 WHERE component_purl = $1 AND scanner_id = $2`
	expectQuery(mock, exists).
		WithArgs(scanID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, lookup).
		WithArgs("pkg:npm/leftpad@1.0.0", scanID).
		WillReturnError(sql.ErrNoRows)
	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", scanID, AnalysisStatusPending).
		WillReturnError(errors.New("boom"))
	if _, err := store.EnqueueAnalysis("pkg:npm/leftpad@1.0.0", scanID); err == nil {
		t.Fatalf("expected insert error")
	}

	queueID := uuid.New()
	expectQuery(mock, exists).
		WithArgs(scanID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, lookup).
		WithArgs("pkg:npm/leftpad@1.0.0", scanID).
		WillReturnError(sql.ErrNoRows)
	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", scanID, AnalysisStatusPending).
		WillReturnRows(sqlmock.NewRows([]string{"id", "component_purl", "scanner_id", "status", "created_at"}).
			AddRow(queueID, "pkg:npm/leftpad@1.0.0", scanID, AnalysisStatusPending, time.Now()))
	if item, err := store.EnqueueAnalysis("pkg:npm/leftpad@1.0.0", scanID); err != nil || item.ID != queueID {
		t.Fatalf("expected queue item")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestUpdateAnalysisQueueStatus(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if err := store.UpdateAnalysisQueueStatus(uuid.New(), "bad"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	queueID := uuid.New()
	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnError(sql.ErrNoRows)
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}

	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(AnalysisStatusCompleted))
	expectExec(mock, `UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`).
		WithArgs(AnalysisStatusProcessing, queueID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); err != nil {
		t.Fatalf("expected transition success")
	}

	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(AnalysisStatusPending))
	expectExec(mock, `UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`).
		WithArgs(AnalysisStatusProcessing, queueID).
		WillReturnError(errors.New("boom"))
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); err == nil {
		t.Fatalf("expected update error")
	}

	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(AnalysisStatusPending))
	expectExec(mock, `UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`).
		WithArgs(AnalysisStatusProcessing, queueID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); err == nil {
		t.Fatalf("expected rows affected error")
	}

	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(AnalysisStatusPending))
	expectExec(mock, `UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`).
		WithArgs(AnalysisStatusProcessing, queueID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found after update")
	}

	expectQuery(mock, `SELECT status FROM source_malware_input_queue WHERE id = $1`).
		WithArgs(queueID).
		WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(AnalysisStatusPending))
	expectExec(mock, `UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`).
		WithArgs(AnalysisStatusProcessing, queueID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.UpdateAnalysisQueueStatus(queueID, AnalysisStatusProcessing); err != nil {
		t.Fatalf("expected update success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestCreateAnalysisResult(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.CreateAnalysisResult(AnalysisResultInput{ComponentPURL: " ", Verdict: "CLEAN"}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if _, err := store.CreateAnalysisResult(AnalysisResultInput{ComponentPURL: "pkg:npm/leftpad@1.0.0", Verdict: "bad"}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid verdict")
	}

	insert := `INSERT INTO source_malware_input_results (
			 component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until`
	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", "", "CLEAN", 0, "", sqlmock.AnyArg(), nil).
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateAnalysisResult(AnalysisResultInput{ComponentPURL: "pkg:npm/leftpad@1.0.0", Verdict: "CLEAN"}); err == nil {
		t.Fatalf("expected insert error")
	}

	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", "", "CLEAN", 0, "", sqlmock.AnyArg(), nil).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := store.CreateAnalysisResult(AnalysisResultInput{ComponentPURL: "pkg:npm/leftpad@1.0.0", Verdict: "CLEAN"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists")
	}

	resultID := uuid.New()
	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", "", "CLEAN", 0, "", sqlmock.AnyArg(), nil).
		WillReturnRows(sqlmock.NewRows([]string{"id", "component_purl", "component_hash", "verdict", "findings_count", "summary", "scanned_at", "valid_until"}).
			AddRow(resultID, "pkg:npm/leftpad@1.0.0", "", "CLEAN", 0, "", time.Now(), nil))
	if result, err := store.CreateAnalysisResult(AnalysisResultInput{ComponentPURL: "pkg:npm/leftpad@1.0.0", Verdict: "CLEAN"}); err != nil || result.ID != resultID {
		t.Fatalf("expected analysis result")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestCreateScanComponentResult(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.CreateScanComponentResult(ScanComponentResultInput{ComponentPURL: " ", ScanID: uuid.New(), SourceID: uuid.New(), DetailsJSON: []byte(`{}`)}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	scanID := uuid.New()
	sourceID := uuid.New()
	resultID := uuid.New()

	sourceExists := `SELECT EXISTS(SELECT 1 FROM scan_malware_source WHERE id = $1)`
	resultPurl := `SELECT component_purl FROM source_malware_input_results WHERE id = $1`
	queuePurl := `SELECT component_purl FROM source_malware_input_queue WHERE id = $1`

	expectQuery(mock, sourceExists).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, resultPurl).
		WithArgs(resultID).
		WillReturnRows(sqlmock.NewRows([]string{"component_purl"}).AddRow("pkg:npm/other@1.0.0"))
	if _, err := store.CreateScanComponentResult(ScanComponentResultInput{
		ComponentPURL:    "pkg:npm/leftpad@1.0.0",
		AnalysisResultID: &resultID,
		ScanID:           scanID,
		SourceID:         sourceID,
		DetailsJSON:      []byte(`{}`),
	}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected scan mismatch")
	}

	expectQuery(mock, sourceExists).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, resultPurl).
		WithArgs(resultID).
		WillReturnRows(sqlmock.NewRows([]string{"component_purl"}).AddRow("pkg:npm/leftpad@1.0.0"))
	expectQuery(mock, queuePurl).
		WithArgs(scanID).
		WillReturnRows(sqlmock.NewRows([]string{"component_purl"}).AddRow("pkg:npm/leftpad@1.0.0"))
	insert := `INSERT INTO source_malware_input_component_results (
			 component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING id, component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware, created_at`
	rowID := uuid.New()
	expectQuery(mock, insert).
		WithArgs("pkg:npm/leftpad@1.0.0", "", resultID, scanID, sourceID, "MAL-1.json", "", sqlmock.AnyArg(), nil, nil, "", "", true).
		WillReturnRows(sqlmock.NewRows([]string{"id", "component_purl", "component_hash", "analysis_result_id", "scan_id", "source_id", "result_filename", "evidence", "details_json", "published_at", "modified_at", "detect_version", "fixed_version", "is_malware", "created_at"}).
			AddRow(rowID, "pkg:npm/leftpad@1.0.0", "", resultID, scanID, sourceID, "MAL-1.json", "", []byte(`{}`), nil, nil, "", "", true, time.Now()))
	if result, err := store.CreateScanComponentResult(ScanComponentResultInput{
		ComponentPURL:    "pkg:npm/leftpad@1.0.0",
		AnalysisResultID: &resultID,
		ScanID:           scanID,
		SourceID:         sourceID,
		ResultFilename:   "MAL-1.json",
		DetailsJSON:      []byte(`{}`),
		IsMalware:        true,
	}); err != nil || result.ID != rowID {
		t.Fatalf("expected scan component result")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestGetLatestScanComponentResultTimestamp(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.GetLatestScanComponentResultTimestamp(uuid.Nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	sourceID := uuid.New()
	query := `SELECT MAX(COALESCE(modified_at, published_at, created_at))
		 FROM source_malware_input_component_results
		 WHERE source_id = $1`

	expectQuery(mock, query).
		WithArgs(sourceID).
		WillReturnError(errors.New("boom"))
	if _, err := store.GetLatestScanComponentResultTimestamp(sourceID); err == nil {
		t.Fatalf("expected query error")
	}

	expectQuery(mock, query).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(nil))
	if result, err := store.GetLatestScanComponentResultTimestamp(sourceID); err != nil || result != nil {
		t.Fatalf("expected nil timestamp")
	}

	now := time.Now().UTC()
	expectQuery(mock, query).
		WithArgs(sourceID).
		WillReturnRows(sqlmock.NewRows([]string{"max"}).AddRow(now))
	if result, err := store.GetLatestScanComponentResultTimestamp(sourceID); err != nil || result == nil || !result.Equal(now) {
		t.Fatalf("expected timestamp")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
