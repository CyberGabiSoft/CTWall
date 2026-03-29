package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

// CreateScanMalwareSource registers a malware data source in Postgres.
func (s *PostgresStore) CreateScanMalwareSource(name, sourceType, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error) {
	name = strings.TrimSpace(name)
	baseURL = strings.TrimSpace(baseURL)
	if name == "" || baseURL == "" {
		return nil, ErrInvalidPayload
	}
	if !isValidMalwareSourceType(sourceType) {
		return nil, ErrInvalidPayload
	}
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO scan_malware_source (name, source_type, base_url, config_json, is_active)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, name, source_type, base_url, config_json, is_active, created_at`,
		name,
		normalizeMalwareSourceType(sourceType),
		baseURL,
		config,
		isActive,
	)
	return scanMalwareSource(row)
}

// ListScanMalwareSources returns all malware sources.
func (s *PostgresStore) ListScanMalwareSources() ([]*models.ScanMalwareSource, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, source_type, base_url, config_json, is_active, created_at
		 FROM scan_malware_source
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]*models.ScanMalwareSource, 0)
	for rows.Next() {
		source, err := scanMalwareSourceRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, source)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// GetScanMalwareSource returns a malware source by ID.
func (s *PostgresStore) GetScanMalwareSource(id uuid.UUID) (*models.ScanMalwareSource, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, source_type, base_url, config_json, is_active, created_at
		 FROM scan_malware_source
		 WHERE id = $1`,
		id,
	)
	source, err := scanMalwareSource(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return source, nil
}

// GetScanMalwareSourceByName returns a malware source by name and type.
func (s *PostgresStore) GetScanMalwareSourceByName(name, sourceType string) (*models.ScanMalwareSource, error) {
	name = strings.TrimSpace(name)
	sourceType = strings.TrimSpace(sourceType)
	if name == "" {
		return nil, ErrInvalidPayload
	}
	if !isValidMalwareSourceType(sourceType) {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, source_type, base_url, config_json, is_active, created_at
		 FROM scan_malware_source
		 WHERE name = $1 AND source_type = $2`,
		name,
		normalizeMalwareSourceType(sourceType),
	)
	source, err := scanMalwareSource(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return source, nil
}

// EnsureScanMalwareSource ensures a malware source exists or updates it if present.
func (s *PostgresStore) EnsureScanMalwareSource(name, sourceType, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error) {
	name = strings.TrimSpace(name)
	baseURL = strings.TrimSpace(baseURL)
	if name == "" || baseURL == "" {
		return nil, ErrInvalidPayload
	}
	if !isValidMalwareSourceType(sourceType) {
		return nil, ErrInvalidPayload
	}
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	ctx, cancel := s.ctx()
	defer cancel()

	var existingID uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM scan_malware_source WHERE name = $1 AND source_type = $2`,
		name,
		normalizeMalwareSourceType(sourceType),
	).Scan(&existingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return s.CreateScanMalwareSource(name, sourceType, baseURL, config, isActive)
	}

	row := s.db.QueryRowContext(ctx,
		`UPDATE scan_malware_source
		 SET base_url = $1, config_json = $2, is_active = $3
		 WHERE id = $4
		 RETURNING id, name, source_type, base_url, config_json, is_active, created_at`,
		baseURL,
		config,
		isActive,
		existingID,
	)
	return scanMalwareSource(row)
}

// UpdateScanMalwareSource updates a malware source.
func (s *PostgresStore) UpdateScanMalwareSource(id uuid.UUID, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return nil, ErrInvalidPayload
	}
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`UPDATE scan_malware_source
		 SET base_url = $1, config_json = $2, is_active = $3
		 WHERE id = $4
		 RETURNING id, name, source_type, base_url, config_json, is_active, created_at`,
		baseURL,
		config,
		isActive,
		id,
	)
	source, err := scanMalwareSource(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return source, nil
}

// CreateScanner registers a scanner in Postgres.
func (s *PostgresStore) CreateScanner(sourceID uuid.UUID, name, scannerType, version, resultsPath string, config json.RawMessage) (*models.Scanner, error) {
	name = strings.TrimSpace(name)
	scannerType = strings.TrimSpace(scannerType)
	version = strings.TrimSpace(version)
	resultsPath = strings.TrimSpace(resultsPath)
	if name == "" || scannerType == "" {
		return nil, ErrInvalidPayload
	}
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := ensureSourceExists(ctx, s.db, sourceID); err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO source_scanners (source_id, name, scanner_type, version, results_path, config_json)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, source_id, name, scanner_type, version, results_path, config_json, created_at`,
		sourceID,
		name,
		scannerType,
		version,
		resultsPath,
		config,
	)
	return scanScanner(row)
}

// ListScanners returns all source_scanners.
func (s *PostgresStore) ListScanners() ([]*models.Scanner, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, source_id, name, scanner_type, version, results_path, config_json, created_at
		 FROM source_scanners
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]*models.Scanner, 0)
	for rows.Next() {
		item, err := scanScannerRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// EnsureScanner ensures a scanner exists or updates it if present.
func (s *PostgresStore) EnsureScanner(sourceID uuid.UUID, name, scannerType, version, resultsPath string, config json.RawMessage) (*models.Scanner, error) {
	name = strings.TrimSpace(name)
	scannerType = strings.TrimSpace(scannerType)
	version = strings.TrimSpace(version)
	resultsPath = strings.TrimSpace(resultsPath)
	if name == "" || scannerType == "" {
		return nil, ErrInvalidPayload
	}
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := ensureSourceExists(ctx, s.db, sourceID); err != nil {
		return nil, err
	}

	var existingID uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM source_scanners WHERE source_id = $1 AND name = $2`,
		sourceID,
		name,
	).Scan(&existingID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return s.CreateScanner(sourceID, name, scannerType, version, resultsPath, config)
	}

	row := s.db.QueryRowContext(ctx,
		`UPDATE source_scanners
		 SET scanner_type = $1, version = $2, results_path = $3, config_json = $4
		 WHERE id = $5
		 RETURNING id, source_id, name, scanner_type, version, results_path, config_json, created_at`,
		scannerType,
		version,
		resultsPath,
		config,
		existingID,
	)
	return scanScanner(row)
}

// EnqueueAnalysis creates a pending analysis queue item.
func (s *PostgresStore) EnqueueAnalysis(componentPURL string, scannerID uuid.UUID) (*models.AnalysisQueueItem, error) {
	return s.UpsertAnalysisQueue(componentPURL, scannerID, AnalysisStatusPending)
}

// UpsertAnalysisQueue creates or updates an analysis queue item.
func (s *PostgresStore) UpsertAnalysisQueue(componentPURL string, scannerID uuid.UUID, status string) (*models.AnalysisQueueItem, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" || scannerID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if !isValidAnalysisStatus(status) {
		return nil, ErrInvalidPayload
	}
	normalized := normalizeAnalysisStatus(status)

	ctx, cancel := s.ctx()
	defer cancel()

	if err := ensureScannerExists(ctx, s.db, scannerID); err != nil {
		return nil, err
	}

	var existingID uuid.UUID
	var current string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, status
		 FROM source_malware_input_queue
		 WHERE component_purl = $1 AND scanner_id = $2`,
		componentPURL,
		scannerID,
	).Scan(&existingID, &current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, sql.ErrNoRows) {
		row := s.db.QueryRowContext(ctx,
			`INSERT INTO source_malware_input_queue (component_purl, scanner_id, status)
			 VALUES ($1, $2, $3)
			 RETURNING id, component_purl, scanner_id, status, created_at`,
			componentPURL,
			scannerID,
			normalized,
		)
		return scanAnalysisQueueItem(row)
	}
	if !analysisState.CanTransition(current, normalized) {
		return nil, ErrInvalidStateTransition
	}
	row := s.db.QueryRowContext(ctx,
		`UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2
		 RETURNING id, component_purl, scanner_id, status, created_at`,
		normalized,
		existingID,
	)
	return scanAnalysisQueueItem(row)
}

// UpdateAnalysisQueueStatus updates a queued analysis status.
func (s *PostgresStore) UpdateAnalysisQueueStatus(id uuid.UUID, status string) error {
	if !isValidAnalysisStatus(status) {
		return ErrInvalidPayload
	}
	normalized := normalizeAnalysisStatus(status)

	ctx, cancel := s.ctx()
	defer cancel()

	var current string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status FROM source_malware_input_queue WHERE id = $1`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !analysisState.CanTransition(current, normalized) {
		return ErrInvalidStateTransition
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE source_malware_input_queue
		 SET status = $1
		 WHERE id = $2`, normalized, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateAnalysisResult stores a summarized analysis result.
func (s *PostgresStore) CreateAnalysisResult(input AnalysisResultInput) (*models.AnalysisResult, error) {
	componentPURL := strings.TrimSpace(input.ComponentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	if !isValidAnalysisVerdict(input.Verdict) {
		return nil, ErrInvalidPayload
	}
	scannedAt := time.Now().UTC()
	if input.ScannedAt != nil {
		scannedAt = input.ScannedAt.UTC()
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO source_malware_input_results (
			 component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until`,
		componentPURL,
		strings.TrimSpace(input.ComponentHash),
		normalizeAnalysisVerdict(input.Verdict),
		input.FindingsCount,
		strings.TrimSpace(input.Summary),
		scannedAt,
		input.ValidUntil,
	)
	if result, err := scanAnalysisResult(row); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	} else {
		return result, nil
	}
}

// UpsertAnalysisResultFromFindings aggregates source_malware_input_component_results into source_malware_input_results.
func (s *PostgresStore) UpsertAnalysisResultFromFindings(componentPURL, componentHash, summary string) (*models.AnalysisResult, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	scannedAt := time.Now().UTC()
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`WITH stats AS (
			 SELECT COUNT(*) AS findings_count,
			        COALESCE(bool_or(is_malware), FALSE) AS has_malware
			 FROM source_malware_input_component_results
			 WHERE component_purl = $1
		 )
		 INSERT INTO source_malware_input_results (
			 component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 )
		 SELECT $1,
		        $2,
		        CASE WHEN stats.has_malware THEN 'MALWARE' ELSE 'CLEAN' END,
		        stats.findings_count,
		        $3,
		        $4,
		        NULL
		 FROM stats
		 ON CONFLICT (component_purl) DO UPDATE SET
			 component_hash = EXCLUDED.component_hash,
			 verdict = EXCLUDED.verdict,
			 findings_count = EXCLUDED.findings_count,
			 summary = EXCLUDED.summary,
			 scanned_at = EXCLUDED.scanned_at,
			 valid_until = EXCLUDED.valid_until
		 RETURNING id, component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until`,
		componentPURL,
		strings.TrimSpace(componentHash),
		strings.TrimSpace(summary),
		scannedAt,
	)
	return scanAnalysisResult(row)
}

// ListAnalysisResults returns analysis summaries optionally filtered by PURL.
func (s *PostgresStore) ListAnalysisResults(componentPURL string) ([]models.AnalysisResult, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 FROM source_malware_input_results`
	args := []any{}
	if componentPURL != "" {
		query += " WHERE component_purl = $1"
		args = append(args, componentPURL)
	}
	query += " ORDER BY scanned_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]models.AnalysisResult, 0)
	for rows.Next() {
		var result models.AnalysisResult
		var componentHash sql.NullString
		var summary sql.NullString
		if err := rows.Scan(&result.ID, &result.ComponentPURL, &componentHash, &result.Verdict, &result.FindingsCount, &summary, &result.ScannedAt, &result.ValidUntil); err != nil {
			return nil, err
		}
		result.ComponentPURL = strings.TrimSpace(result.ComponentPURL)
		result.ComponentHash = strings.TrimSpace(componentHash.String)
		result.Verdict = normalizeAnalysisVerdict(result.Verdict)
		result.Summary = strings.TrimSpace(summary.String)
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// CreateScanComponentResult stores a raw scan finding.
func (s *PostgresStore) CreateScanComponentResult(input ScanComponentResultInput) (*models.ScanComponentResult, error) {
	componentPURL := strings.TrimSpace(input.ComponentPURL)
	if componentPURL == "" || input.ScanID == uuid.Nil || input.SourceID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if len(input.DetailsJSON) == 0 {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := ensureSourceExists(ctx, s.db, input.SourceID); err != nil {
		return nil, err
	}
	if input.AnalysisResultID != nil {
		resultPURL, err := fetchAnalysisResultComponentPURL(ctx, s.db, *input.AnalysisResultID)
		if err != nil {
			return nil, err
		}
		if resultPURL != componentPURL {
			return nil, ErrInvalidPayload
		}
	}
	if err := ensureQueueMatchesComponent(ctx, s.db, input.ScanID, componentPURL); err != nil {
		return nil, err
	}

	var analysisResultID any
	if input.AnalysisResultID != nil {
		analysisResultID = *input.AnalysisResultID
	}

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO source_malware_input_component_results (
			 component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 RETURNING id, component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware, created_at`,
		componentPURL,
		strings.TrimSpace(input.ComponentHash),
		analysisResultID,
		input.ScanID,
		input.SourceID,
		strings.TrimSpace(input.ResultFilename),
		strings.TrimSpace(input.Evidence),
		input.DetailsJSON,
		input.PublishedAt,
		input.ModifiedAt,
		strings.TrimSpace(input.DetectVersion),
		strings.TrimSpace(input.FixedVersion),
		input.IsMalware,
	)
	return scanScanComponentResult(row)
}

// UpsertScanComponentResult stores or updates a scan finding.
func (s *PostgresStore) UpsertScanComponentResult(input ScanComponentResultInput) (*models.ScanComponentResult, error) {
	componentPURL := strings.TrimSpace(input.ComponentPURL)
	if componentPURL == "" || input.ScanID == uuid.Nil || input.SourceID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if len(input.DetailsJSON) == 0 {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := ensureSourceExists(ctx, s.db, input.SourceID); err != nil {
		return nil, err
	}
	if input.AnalysisResultID != nil {
		resultPURL, err := fetchAnalysisResultComponentPURL(ctx, s.db, *input.AnalysisResultID)
		if err != nil {
			return nil, err
		}
		if resultPURL != componentPURL {
			return nil, ErrInvalidPayload
		}
	}
	if err := ensureQueueMatchesComponent(ctx, s.db, input.ScanID, componentPURL); err != nil {
		return nil, err
	}

	var analysisResultID any
	if input.AnalysisResultID != nil {
		analysisResultID = *input.AnalysisResultID
	}

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO source_malware_input_component_results (
			 component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (component_purl, source_id, result_filename) DO UPDATE SET
			 component_hash = EXCLUDED.component_hash,
			 analysis_result_id = EXCLUDED.analysis_result_id,
			 evidence = EXCLUDED.evidence,
			 details_json = EXCLUDED.details_json,
			 published_at = EXCLUDED.published_at,
			 modified_at = EXCLUDED.modified_at,
			 detect_version = EXCLUDED.detect_version,
			 fixed_version = EXCLUDED.fixed_version,
			 is_malware = EXCLUDED.is_malware
		 RETURNING id, component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware, created_at`,
		componentPURL,
		strings.TrimSpace(input.ComponentHash),
		analysisResultID,
		input.ScanID,
		input.SourceID,
		strings.TrimSpace(input.ResultFilename),
		strings.TrimSpace(input.Evidence),
		input.DetailsJSON,
		input.PublishedAt,
		input.ModifiedAt,
		strings.TrimSpace(input.DetectVersion),
		strings.TrimSpace(input.FixedVersion),
		input.IsMalware,
	)
	return scanScanComponentResult(row)
}

// ListScanComponentResults returns scan findings optionally filtered by PURL.
func (s *PostgresStore) ListScanComponentResults(componentPURL string, sourceID *uuid.UUID, limit, offset int) ([]models.ScanComponentResult, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if limit <= 0 || offset < 0 {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, component_purl, component_hash, analysis_result_id, scan_id, source_id, result_filename, evidence, details_json, published_at, modified_at, detect_version, fixed_version, is_malware, created_at
		 FROM source_malware_input_component_results`
	args := []any{}
	if componentPURL != "" {
		query += " WHERE component_purl = $1"
		args = append(args, componentPURL)
	}
	if sourceID != nil && *sourceID != uuid.Nil {
		if len(args) == 0 {
			query += " WHERE source_id = $1"
		} else {
			query += fmt.Sprintf(" AND source_id = $%d", len(args)+1)
		}
		args = append(args, *sourceID)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]models.ScanComponentResult, 0)
	for rows.Next() {
		var result models.ScanComponentResult
		var analysisResultID uuid.NullUUID
		if err := rows.Scan(
			&result.ID,
			&result.ComponentPURL,
			&result.ComponentHash,
			&analysisResultID,
			&result.ScanID,
			&result.SourceID,
			&result.ResultFilename,
			&result.Evidence,
			&result.DetailsJSON,
			&result.PublishedAt,
			&result.ModifiedAt,
			&result.DetectVersion,
			&result.FixedVersion,
			&result.IsMalware,
			&result.CreatedAt,
		); err != nil {
			return nil, err
		}
		result.ComponentPURL = strings.TrimSpace(result.ComponentPURL)
		result.ComponentHash = strings.TrimSpace(result.ComponentHash)
		result.ResultFilename = strings.TrimSpace(result.ResultFilename)
		result.Evidence = strings.TrimSpace(result.Evidence)
		result.DetectVersion = strings.TrimSpace(result.DetectVersion)
		result.FixedVersion = strings.TrimSpace(result.FixedVersion)
		if analysisResultID.Valid {
			id := analysisResultID.UUID
			result.AnalysisResultID = &id
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// PruneScanComponentResultsForSource deletes stored OSV findings for a source whose result_filename is no longer present.
// This is intended for full syncs where we have the authoritative list of MAL-*.json entries.
func (s *PostgresStore) PruneScanComponentResultsForSource(sourceID uuid.UUID, keepResultFilenames []string) (int, []string, error) {
	if sourceID == uuid.Nil {
		return 0, nil, ErrInvalidPayload
	}
	if len(keepResultFilenames) == 0 {
		return 0, nil, ErrInvalidPayload
	}
	keep := make([]string, 0, len(keepResultFilenames))
	seen := make(map[string]struct{}, len(keepResultFilenames))
	for _, filename := range keepResultFilenames {
		trimmed := strings.TrimSpace(filename)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		keep = append(keep, trimmed)
	}
	if len(keep) == 0 {
		return 0, nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	// DELETE returns per-row component_purl; collect affected PURLs so callers can repair aggregated results.
	// NOTE: `keep` is passed as a text[] parameter (pgx stdlib supports []string encoding).
	rows, err := s.db.QueryContext(ctx,
		`WITH deleted AS (
			 DELETE FROM source_malware_input_component_results
			 WHERE source_id = $1
			   AND result_filename LIKE 'MAL-%'
			   AND NOT (result_filename = ANY($2::text[]))
			 RETURNING component_purl
		 )
		 SELECT component_purl FROM deleted`,
		sourceID,
		keep,
	)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()

	deletedCount := 0
	affectedSet := make(map[string]struct{}, 64)
	for rows.Next() {
		var purl string
		if err := rows.Scan(&purl); err != nil {
			return 0, nil, err
		}
		purl = strings.TrimSpace(purl)
		if purl != "" {
			affectedSet[purl] = struct{}{}
		}
		deletedCount++
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}

	affected := make([]string, 0, len(affectedSet))
	for purl := range affectedSet {
		affected = append(affected, purl)
	}
	return deletedCount, affected, nil
}

// RepairAnalysisResults recomputes verdict/findings_count for the given component PURLs based on raw findings.
// It preserves existing summary/component_hash when there are still findings, and clears them when findings_count = 0.
func (s *PostgresStore) RepairAnalysisResults(componentPURLs []string) error {
	if len(componentPURLs) == 0 {
		return ErrInvalidPayload
	}
	unique := make([]string, 0, len(componentPURLs))
	seen := make(map[string]struct{}, len(componentPURLs))
	for _, purl := range componentPURLs {
		trimmed := strings.TrimSpace(purl)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		unique = append(unique, trimmed)
	}
	if len(unique) == 0 {
		return ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	_, err := s.db.ExecContext(ctx,
		`WITH affected AS (
			 SELECT unnest($1::text[]) AS component_purl
		 ),
		 stats AS (
			 SELECT a.component_purl,
			        COUNT(r.id) AS findings_count,
			        COALESCE(bool_or(r.is_malware), FALSE) AS has_malware
			 FROM affected a
			 LEFT JOIN source_malware_input_component_results r
			   ON r.component_purl = a.component_purl
			 GROUP BY a.component_purl
		 )
		 INSERT INTO source_malware_input_results (
			 component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 )
		 SELECT component_purl,
		        NULL,
		        CASE WHEN stats.has_malware THEN 'MALWARE' ELSE 'CLEAN' END,
		        stats.findings_count,
		        NULL,
		        NOW(),
		        NULL
		 FROM stats
		 ON CONFLICT (component_purl) DO UPDATE SET
			 verdict = EXCLUDED.verdict,
			 findings_count = EXCLUDED.findings_count,
			 scanned_at = EXCLUDED.scanned_at,
			 valid_until = EXCLUDED.valid_until,
			 summary = CASE
				WHEN EXCLUDED.findings_count = 0 THEN NULL
				ELSE source_malware_input_results.summary
			 END,
			 component_hash = CASE
				WHEN EXCLUDED.findings_count = 0 THEN NULL
				ELSE source_malware_input_results.component_hash
			 END`,
		unique,
	)
	return err
}

// GetLatestScanComponentResultTimestamp returns the newest timestamp for a source's findings.
func (s *PostgresStore) GetLatestScanComponentResultTimestamp(sourceID uuid.UUID) (*time.Time, error) {
	if sourceID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	var latest sql.NullTime
	if err := s.db.QueryRowContext(ctx,
		`SELECT MAX(COALESCE(modified_at, published_at, created_at))
		 FROM source_malware_input_component_results
		 WHERE source_id = $1`,
		sourceID,
	).Scan(&latest); err != nil {
		return nil, err
	}
	if !latest.Valid {
		return nil, nil
	}
	value := latest.Time
	return &value, nil
}

func scanMalwareSource(row *sql.Row) (*models.ScanMalwareSource, error) {
	var source models.ScanMalwareSource
	if err := row.Scan(&source.ID, &source.Name, &source.SourceType, &source.BaseURL, &source.ConfigJSON, &source.IsActive, &source.CreatedAt); err != nil {
		return nil, err
	}
	return &source, nil
}

func scanMalwareSourceRow(rows *sql.Rows) (*models.ScanMalwareSource, error) {
	var source models.ScanMalwareSource
	if err := rows.Scan(&source.ID, &source.Name, &source.SourceType, &source.BaseURL, &source.ConfigJSON, &source.IsActive, &source.CreatedAt); err != nil {
		return nil, err
	}
	return &source, nil
}

func scanScanner(row *sql.Row) (*models.Scanner, error) {
	var scanner models.Scanner
	if err := row.Scan(&scanner.ID, &scanner.SourceID, &scanner.Name, &scanner.ScannerType, &scanner.Version, &scanner.ResultsPath, &scanner.ConfigJSON, &scanner.CreatedAt); err != nil {
		return nil, err
	}
	return &scanner, nil
}

func scanScannerRow(rows *sql.Rows) (*models.Scanner, error) {
	var scanner models.Scanner
	if err := rows.Scan(&scanner.ID, &scanner.SourceID, &scanner.Name, &scanner.ScannerType, &scanner.Version, &scanner.ResultsPath, &scanner.ConfigJSON, &scanner.CreatedAt); err != nil {
		return nil, err
	}
	return &scanner, nil
}

func scanAnalysisQueueItem(row *sql.Row) (*models.AnalysisQueueItem, error) {
	var item models.AnalysisQueueItem
	if err := row.Scan(
		&item.ID,
		&item.ComponentPURL,
		&item.ScannerID,
		&item.Status,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	item.ComponentPURL = strings.TrimSpace(item.ComponentPURL)
	item.Status = normalizeAnalysisStatus(item.Status)
	return &item, nil
}

func scanAnalysisResult(row *sql.Row) (*models.AnalysisResult, error) {
	var result models.AnalysisResult
	var componentHash sql.NullString
	var summary sql.NullString
	if err := row.Scan(&result.ID, &result.ComponentPURL, &componentHash, &result.Verdict, &result.FindingsCount, &summary, &result.ScannedAt, &result.ValidUntil); err != nil {
		return nil, err
	}
	result.ComponentPURL = strings.TrimSpace(result.ComponentPURL)
	result.ComponentHash = strings.TrimSpace(componentHash.String)
	result.Verdict = normalizeAnalysisVerdict(result.Verdict)
	result.Summary = strings.TrimSpace(summary.String)
	return &result, nil
}

func scanScanComponentResult(row *sql.Row) (*models.ScanComponentResult, error) {
	var result models.ScanComponentResult
	var analysisResultID uuid.NullUUID
	if err := row.Scan(
		&result.ID,
		&result.ComponentPURL,
		&result.ComponentHash,
		&analysisResultID,
		&result.ScanID,
		&result.SourceID,
		&result.ResultFilename,
		&result.Evidence,
		&result.DetailsJSON,
		&result.PublishedAt,
		&result.ModifiedAt,
		&result.DetectVersion,
		&result.FixedVersion,
		&result.IsMalware,
		&result.CreatedAt,
	); err != nil {
		return nil, err
	}
	result.ComponentPURL = strings.TrimSpace(result.ComponentPURL)
	result.ComponentHash = strings.TrimSpace(result.ComponentHash)
	result.ResultFilename = strings.TrimSpace(result.ResultFilename)
	result.Evidence = strings.TrimSpace(result.Evidence)
	result.DetectVersion = strings.TrimSpace(result.DetectVersion)
	result.FixedVersion = strings.TrimSpace(result.FixedVersion)
	if analysisResultID.Valid {
		id := analysisResultID.UUID
		result.AnalysisResultID = &id
	}
	return &result, nil
}

func ensureSourceExists(ctx context.Context, db *sql.DB, sourceID uuid.UUID) error {
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM scan_malware_source WHERE id = $1)`, sourceID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func ensureScannerExists(ctx context.Context, db *sql.DB, scanID uuid.UUID) error {
	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM source_scanners WHERE id = $1)`, scanID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func fetchAnalysisResultComponentPURL(ctx context.Context, db *sql.DB, analysisResultID uuid.UUID) (string, error) {
	var componentPURL string
	if err := db.QueryRowContext(ctx,
		`SELECT component_purl FROM source_malware_input_results WHERE id = $1`, analysisResultID).Scan(&componentPURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return strings.TrimSpace(componentPURL), nil
}

func ensureQueueMatchesComponent(ctx context.Context, db *sql.DB, queueID uuid.UUID, componentPURL string) error {
	var stored string
	if err := db.QueryRowContext(ctx,
		`SELECT component_purl FROM source_malware_input_queue WHERE id = $1`, queueID).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if strings.TrimSpace(stored) != strings.TrimSpace(componentPURL) {
		return ErrInvalidPayload
	}
	return nil
}
