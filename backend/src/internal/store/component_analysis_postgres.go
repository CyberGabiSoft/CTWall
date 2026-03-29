package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// EnqueueComponentAnalysis inserts a new component analysis queue item.
func (s *PostgresStore) EnqueueComponentAnalysis(componentPURL, reason string, scheduledFor *time.Time) (*models.ComponentAnalysisQueueItem, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" || !isValidComponentAnalysisReason(reason) {
		return nil, ErrInvalidPayload
	}
	normalizedReason := normalizeComponentAnalysisReason(reason)

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO component_analysis_malware_queue (
			 component_purl, status, reason, attempts, scheduled_for
		 )
		 VALUES ($1, $2, $3, 0, $4)
		 ON CONFLICT (component_purl) WHERE status IN ('PENDING','PROCESSING') DO UPDATE SET
			 reason = EXCLUDED.reason,
			 scheduled_for = COALESCE(EXCLUDED.scheduled_for, component_analysis_malware_queue.scheduled_for),
			 updated_at = NOW()
		 RETURNING id, component_purl, status, reason, attempts, last_error, locked_at, locked_by, scheduled_for, created_at, updated_at, completed_at`,
		componentPURL,
		ComponentAnalysisStatusPending,
		normalizedReason,
		scheduledFor,
	)
	return scanComponentAnalysisQueueItem(row)
}

// EnqueueComponentAnalysisBatch inserts component analysis jobs for the given PURLs.
func (s *PostgresStore) EnqueueComponentAnalysisBatch(componentPURLs []string, reason string, scheduledFor *time.Time) (int, error) {
	if len(componentPURLs) == 0 {
		return 0, nil
	}
	if !isValidComponentAnalysisReason(reason) {
		return 0, ErrInvalidPayload
	}
	normalizedReason := normalizeComponentAnalysisReason(reason)
	unique := make([]string, 0, len(componentPURLs))
	seen := make(map[string]struct{}, len(componentPURLs))
	for _, raw := range componentPURLs {
		purl := strings.TrimSpace(raw)
		if purl == "" {
			continue
		}
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}
		unique = append(unique, purl)
	}
	if len(unique) == 0 {
		return 0, nil
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`WITH input AS (
			 SELECT DISTINCT UNNEST($1::text[]) AS component_purl
		 ),
		 fresh AS (
			 SELECT DISTINCT component_purl
			 FROM component_analysis_malware_component_state
			 WHERE valid_until IS NULL OR valid_until > NOW()
		 ),
		 candidates AS (
			 SELECT i.component_purl
			 FROM input i
			 LEFT JOIN fresh f ON f.component_purl = i.component_purl
			 WHERE f.component_purl IS NULL
		 )
		 INSERT INTO component_analysis_malware_queue (
			 component_purl, status, reason, attempts, scheduled_for
		 )
		 SELECT component_purl, $2, $3, 0, $4
		 FROM candidates
		 ON CONFLICT (component_purl) WHERE status IN ('PENDING','PROCESSING') DO UPDATE SET
			 reason = EXCLUDED.reason,
			 scheduled_for = COALESCE(EXCLUDED.scheduled_for, component_analysis_malware_queue.scheduled_for),
			 updated_at = NOW()
		 RETURNING id`,
		pgtype.FlatArray[string](unique),
		ComponentAnalysisStatusPending,
		normalizedReason,
		scheduledFor,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

// EnqueueStaleComponentAnalysis enqueues stale or missing mappings for active revisions.
// limit <= 0 means "no limit" (not recommended for large installations).
func (s *PostgresStore) EnqueueStaleComponentAnalysis(reason string, scheduledFor *time.Time, limit int) (int, error) {
	if !isValidComponentAnalysisReason(reason) {
		return 0, ErrInvalidPayload
	}
	normalizedReason := normalizeComponentAnalysisReason(reason)
	if limit < 0 {
		limit = 0
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`WITH active_components AS (
			 SELECT DISTINCT c.purl AS component_purl
			 FROM components c
			 JOIN test_revisions r ON r.id = c.revision_id
			 WHERE r.is_active = TRUE
		 ),
		 stale AS (
			 SELECT ac.component_purl
			 FROM active_components ac
			 LEFT JOIN component_analysis_malware_component_state s
			   ON s.component_purl = ac.component_purl
			 LEFT JOIN component_analysis_malware_queue q
			   ON q.component_purl = ac.component_purl
			  AND q.status IN ('PENDING', 'PROCESSING')
			 WHERE (
			      s.component_purl IS NULL
			      OR (s.valid_until IS NOT NULL AND s.valid_until <= NOW())
			 )
			   AND q.component_purl IS NULL
			 LIMIT NULLIF($4, 0)
		 ),
		 ins AS (
			 INSERT INTO component_analysis_malware_queue (
				 component_purl, status, reason, attempts, scheduled_for
			 )
			 SELECT component_purl, $1, $2, 0, $3
			 FROM stale
			 ON CONFLICT (component_purl) WHERE status IN ('PENDING','PROCESSING') DO UPDATE SET
				 reason = EXCLUDED.reason,
				 scheduled_for = COALESCE(EXCLUDED.scheduled_for, component_analysis_malware_queue.scheduled_for),
				 updated_at = NOW()
			 RETURNING 1
		 )
		 SELECT COUNT(*) FROM ins`,
		ComponentAnalysisStatusPending,
		normalizedReason,
		scheduledFor,
		limit,
	)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// UpsertComponentAnalysisMalwareComponentState stores the latest mapping run state for a component PURL.
func (s *PostgresStore) UpsertComponentAnalysisMalwareComponentState(componentPURL string, scannedAt time.Time, validUntil *time.Time) (*models.ComponentAnalysisMalwareComponentState, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	scannedAt = scannedAt.UTC()
	var normalizedValidUntil *time.Time
	if validUntil != nil {
		value := validUntil.UTC()
		normalizedValidUntil = &value
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO component_analysis_malware_component_state (
			 component_purl, scanned_at, valid_until
		 )
		 VALUES ($1, $2, $3)
		 ON CONFLICT (component_purl) DO UPDATE SET
		     scanned_at = EXCLUDED.scanned_at,
		     valid_until = EXCLUDED.valid_until,
		     updated_at = NOW()
		 RETURNING component_purl, scanned_at, valid_until, updated_at`,
		componentPURL,
		scannedAt,
		normalizedValidUntil,
	)
	var state models.ComponentAnalysisMalwareComponentState
	if err := row.Scan(&state.ComponentPURL, &state.ScannedAt, &state.ValidUntil, &state.UpdatedAt); err != nil {
		return nil, err
	}
	state.ComponentPURL = strings.TrimSpace(state.ComponentPURL)
	return &state, nil
}

// GetComponentAnalysisMalwareSchedule returns the current schedule configuration.
func (s *PostgresStore) GetComponentAnalysisMalwareSchedule() (*models.ComponentAnalysisMalwareSchedule, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT enabled, interval_seconds, updated_at
		 FROM component_analysis_malware_schedule
		 WHERE id = 1`)
	var schedule models.ComponentAnalysisMalwareSchedule
	if err := row.Scan(&schedule.Enabled, &schedule.IntervalSeconds, &schedule.UpdatedAt); err != nil {
		return nil, err
	}
	if schedule.IntervalSeconds < 0 {
		schedule.IntervalSeconds = 0
	}
	return &schedule, nil
}

// UpdateComponentAnalysisMalwareSchedule updates schedule configuration.
func (s *PostgresStore) UpdateComponentAnalysisMalwareSchedule(enabled bool, intervalSeconds int) (*models.ComponentAnalysisMalwareSchedule, error) {
	if intervalSeconds < 0 {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx,
		`UPDATE component_analysis_malware_schedule
		 SET enabled = $1,
		     interval_seconds = $2,
		     updated_at = NOW()
		 WHERE id = 1
		 RETURNING enabled, interval_seconds, updated_at`,
		enabled,
		intervalSeconds,
	)
	var schedule models.ComponentAnalysisMalwareSchedule
	if err := row.Scan(&schedule.Enabled, &schedule.IntervalSeconds, &schedule.UpdatedAt); err != nil {
		return nil, err
	}

	// Keep component state validity consistent with the current schedule.
	if schedule.Enabled && schedule.IntervalSeconds > 0 {
		if _, err := tx.ExecContext(ctx,
			`UPDATE component_analysis_malware_component_state
			 SET valid_until = scanned_at + ($1 * interval '1 second'),
			     updated_at = NOW()`,
			schedule.IntervalSeconds,
		); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.ExecContext(ctx,
			`UPDATE component_analysis_malware_component_state
			 SET valid_until = NULL,
			     updated_at = NOW()`); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if schedule.IntervalSeconds < 0 {
		schedule.IntervalSeconds = 0
	}
	return &schedule, nil
}

// TouchComponentAnalysisMalwareScheduleCheckpoint updates scheduler checkpoint timestamp.
func (s *PostgresStore) TouchComponentAnalysisMalwareScheduleCheckpoint() (time.Time, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var updatedAt time.Time
	if err := s.db.QueryRowContext(ctx,
		`UPDATE component_analysis_malware_schedule
		 SET updated_at = NOW()
		 WHERE id = 1
		 RETURNING updated_at`,
	).Scan(&updatedAt); err != nil {
		return time.Time{}, err
	}
	return updatedAt.UTC(), nil
}

// ClaimComponentAnalysisJobs claims pending jobs for processing.
func (s *PostgresStore) ClaimComponentAnalysisJobs(limit int, lockedBy string) ([]models.ComponentAnalysisQueueItem, error) {
	if limit <= 0 {
		return nil, ErrInvalidPayload
	}
	lockedBy = strings.TrimSpace(lockedBy)
	if lockedBy == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`WITH next_jobs AS (
			 SELECT id
			 FROM component_analysis_malware_queue
			 WHERE status = $1
			   AND (scheduled_for IS NULL OR scheduled_for <= NOW())
			 ORDER BY created_at
			 FOR UPDATE SKIP LOCKED
			 LIMIT $2
		 )
		 UPDATE component_analysis_malware_queue q
		 SET status = $3,
		     attempts = q.attempts + 1,
		     locked_at = NOW(),
		     locked_by = $4,
		     updated_at = NOW()
		 FROM next_jobs
		 WHERE q.id = next_jobs.id
		 RETURNING q.id, q.component_purl, q.status, q.reason, q.attempts, q.last_error, q.locked_at, q.locked_by, q.scheduled_for, q.created_at, q.updated_at, q.completed_at`,
		ComponentAnalysisStatusPending,
		limit,
		ComponentAnalysisStatusProcessing,
		lockedBy,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.ComponentAnalysisQueueItem, 0)
	for rows.Next() {
		item, err := scanComponentAnalysisQueueRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// RequeueStaleComponentAnalysisJobs moves stale PROCESSING jobs back to PENDING so that workers can retry them.
//
// This is a safety valve for crashes/abrupt shutdowns: claimed jobs remain in PROCESSING forever otherwise.
// It is safe to retry jobs because component analysis is idempotent (upserts findings + state).
//
// staleAfter defines how old locked_at must be (or locked_at is NULL) to be considered stale.
// limit <= 0 means "no limit" (not recommended for large installations).
func (s *PostgresStore) RequeueStaleComponentAnalysisJobs(staleAfter time.Duration, limit int) (int, error) {
	if staleAfter <= 0 {
		return 0, ErrInvalidPayload
	}
	if limit < 0 {
		return 0, ErrInvalidPayload
	}

	seconds := int(staleAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`WITH candidates AS (
			 SELECT id
			 FROM component_analysis_malware_queue
			 WHERE status = 'PROCESSING'
			   AND (locked_at IS NULL OR locked_at <= NOW() - ($1 * interval '1 second'))
			 ORDER BY locked_at NULLS FIRST, updated_at
			 LIMIT NULLIF($2, 0)
		 )
		 UPDATE component_analysis_malware_queue q
		 SET status = 'PENDING',
		     last_error = 'stale lock recovered (requeued)',
		     locked_at = NULL,
		     locked_by = NULL,
		     updated_at = NOW()
		 FROM candidates c
		 WHERE q.id = c.id
		 RETURNING q.id`,
		seconds,
		limit,
	)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	return count, nil
}

// UpdateComponentAnalysisQueueStatus updates a component analysis queue item status.
func (s *PostgresStore) UpdateComponentAnalysisQueueStatus(id uuid.UUID, status, lastError string) error {
	if !isValidComponentAnalysisStatus(status) {
		return ErrInvalidPayload
	}
	normalized := normalizeComponentAnalysisStatus(status)
	lastError = strings.TrimSpace(lastError)

	ctx, cancel := s.ctx()
	defer cancel()

	var current string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status FROM component_analysis_malware_queue WHERE id = $1`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !componentAnalysisState.CanTransition(current, normalized) {
		return ErrInvalidStateTransition
	}

	completedAt := sql.NullTime{}
	if normalized == ComponentAnalysisStatusCompleted || normalized == ComponentAnalysisStatusFailed {
		completedAt = sql.NullTime{Valid: true, Time: time.Now().UTC()}
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE component_analysis_malware_queue
		 SET status = $1,
		     last_error = $2,
		     completed_at = $3,
		     updated_at = NOW()
		 WHERE id = $4`,
		normalized,
		nullString(lastError),
		nullTime(completedAt),
		id,
	)
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

// ListComponentAnalysisQueue returns queue items matching the filter.
func (s *PostgresStore) ListComponentAnalysisQueue(filter ComponentAnalysisQueueFilter) ([]models.ComponentAnalysisQueueItem, error) {
	if filter.Limit <= 0 {
		return nil, ErrInvalidPayload
	}
	filter.ComponentPURL = strings.TrimSpace(filter.ComponentPURL)
	filter.Status = strings.TrimSpace(filter.Status)
	if filter.Status != "" && !isValidComponentAnalysisStatus(filter.Status) {
		return nil, ErrInvalidPayload
	}

	query := `SELECT id, component_purl, status, reason, attempts, last_error, locked_at, locked_by, scheduled_for, created_at, updated_at, completed_at
		 FROM component_analysis_malware_queue`
	args := []any{}
	clauses := []string{}
	argIdx := 1
	if filter.ComponentPURL != "" {
		clauses = append(clauses, fmt.Sprintf("component_purl = $%d", argIdx))
		args = append(args, filter.ComponentPURL)
		argIdx++
	}
	if filter.Status != "" {
		clauses = append(clauses, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, normalizeComponentAnalysisStatus(filter.Status))
		argIdx++
	}
	if filter.From != nil {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, filter.From.UTC())
		argIdx++
	}
	if filter.To != nil {
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, filter.To.UTC())
		argIdx++
	}
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, filter.Limit, filter.Offset)

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.ComponentAnalysisQueueItem, 0)
	for rows.Next() {
		item, err := scanComponentAnalysisQueueRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// GetComponentAnalysisQueueItem returns a queue item by ID.
func (s *PostgresStore) GetComponentAnalysisQueueItem(id uuid.UUID) (*models.ComponentAnalysisQueueItem, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, component_purl, status, reason, attempts, last_error, locked_at, locked_by, scheduled_for, created_at, updated_at, completed_at
		 FROM component_analysis_malware_queue
		 WHERE id = $1`, id)
	item, err := scanComponentAnalysisQueueItem(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return item, nil
}

// UpsertComponentAnalysisFinding inserts or updates a malware mapping.
func (s *PostgresStore) UpsertComponentAnalysisFinding(input ComponentAnalysisFindingInput) (*models.ComponentAnalysisFinding, error) {
	componentPURL := strings.TrimSpace(input.ComponentPURL)
	malwarePURL := strings.TrimSpace(input.MalwarePURL)
	if componentPURL == "" || malwarePURL == "" || input.SourceMalwareInputResultID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if !isValidComponentAnalysisMatchType(input.MatchType) {
		return nil, ErrInvalidPayload
	}
	matchType := normalizeComponentAnalysisMatchType(input.MatchType)

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO component_analysis_malware_findings (
			 component_purl, malware_purl, source_malware_input_result_id, match_type
		 )
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (component_purl, malware_purl) DO UPDATE SET
			 source_malware_input_result_id = EXCLUDED.source_malware_input_result_id,
			 match_type = EXCLUDED.match_type,
			 updated_at = NOW()
		 RETURNING id, component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at,
		           (xmax = 0) AS inserted,
		           'OPEN'::text AS triage_status,
		           NULL::text AS triage_priority,
		           'P2'::text AS effective_priority`,
		componentPURL,
		malwarePURL,
		input.SourceMalwareInputResultID,
		matchType,
	)
	var finding models.ComponentAnalysisFinding
	var triagePriority sql.NullString
	var inserted bool
	if err := row.Scan(
		&finding.ID,
		&finding.ComponentPURL,
		&finding.MalwarePURL,
		&finding.SourceMalwareInputResultID,
		&finding.MatchType,
		&finding.CreatedAt,
		&finding.UpdatedAt,
		&inserted,
		&finding.TriageStatus,
		&triagePriority,
		&finding.EffectivePriority,
	); err != nil {
		return nil, err
	}
	if triagePriority.Valid {
		finding.TriagePriority = &triagePriority.String
	}

	// Best-effort: ensure malware.detected alert occurrences exist for active contexts.
	// This must run for both INSERT and UPDATE because a mapping can already exist globally
	// while appearing in a new active revision/project context only now.
	if created, err := s.CreateMalwareDetectedAlertOccurrences(finding.ComponentPURL, finding.MalwarePURL); err != nil {
		slog.Error(
			"failed to create malware detected alert occurrences",
			"component", "store.alerts.malware_detected",
			"component_purl", finding.ComponentPURL,
			"malware_purl", finding.MalwarePURL,
			"inserted", inserted,
			"created", created,
			"error", err,
		)
	}

	return &finding, nil
}

// ListComponentAnalysisFindings returns mappings for a component PURL.
func (s *PostgresStore) ListComponentAnalysisFindings(componentPURL string) ([]models.ComponentAnalysisFinding, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT f.id, f.component_purl, f.malware_purl, f.source_malware_input_result_id, f.match_type, f.created_at, f.updated_at,
		        'OPEN'::text AS triage_status,
		        NULL::text AS triage_priority,
		        'P2'::text AS effective_priority
		 FROM component_analysis_malware_findings f
		 JOIN source_malware_input_results r
		   ON r.id = f.source_malware_input_result_id
		 WHERE f.component_purl = $1
		   AND r.verdict = 'MALWARE'
		 ORDER BY f.updated_at DESC`,
		componentPURL,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]models.ComponentAnalysisFinding, 0)
	for rows.Next() {
		finding, err := scanComponentAnalysisFindingRow(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, *finding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// GetComponentAnalysisFinding returns a mapping by ID.
func (s *PostgresStore) GetComponentAnalysisFinding(id uuid.UUID) (*models.ComponentAnalysisFinding, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, component_purl, malware_purl, source_malware_input_result_id, match_type, created_at, updated_at,
		        'OPEN'::text AS triage_status,
		        NULL::text AS triage_priority,
		        'P2'::text AS effective_priority
		 FROM component_analysis_malware_findings
		 WHERE id = $1`, id)
	finding, err := scanComponentAnalysisFinding(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return finding, nil
}

// ListAnalysisResultsForComponentMatch returns malware results matching a component PURL.
func (s *PostgresStore) ListAnalysisResultsForComponentMatch(componentPURL string) ([]models.AnalysisResult, error) {
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	// We match:
	// 1) exact PURL (with version),
	// 2) base PURL without version (prefix match), e.g.:
	//    pkg:npm/@angular/core@16.0.0 -> pkg:npm/@angular/core
	// This avoids a full table scan by keeping the query indexable.
	candidates := []string{componentPURL}
	if idx := strings.LastIndex(componentPURL, "@"); idx > 0 {
		base := strings.TrimSpace(componentPURL[:idx])
		if base != "" && base != componentPURL {
			candidates = append(candidates, base)
		}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, component_purl, component_hash, verdict, findings_count, summary, scanned_at, valid_until
		 FROM source_malware_input_results
		 WHERE component_purl = ANY($1::text[])
		 ORDER BY component_purl`,
		pgtype.FlatArray[string](candidates),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make([]models.AnalysisResult, 0)
	for rows.Next() {
		var result models.AnalysisResult
		var componentHash sql.NullString
		var summary sql.NullString
		if err := rows.Scan(
			&result.ID,
			&result.ComponentPURL,
			&componentHash,
			&result.Verdict,
			&result.FindingsCount,
			&summary,
			&result.ScannedAt,
			&result.ValidUntil,
		); err != nil {
			return nil, err
		}
		result.ComponentHash = strings.TrimSpace(componentHash.String)
		result.Summary = strings.TrimSpace(summary.String)
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func scanComponentAnalysisQueueItem(row *sql.Row) (*models.ComponentAnalysisQueueItem, error) {
	var item models.ComponentAnalysisQueueItem
	var lastError sql.NullString
	var lockedAt sql.NullTime
	var lockedBy sql.NullString
	var scheduledFor sql.NullTime
	var completedAt sql.NullTime
	if err := row.Scan(
		&item.ID,
		&item.ComponentPURL,
		&item.Status,
		&item.Reason,
		&item.Attempts,
		&lastError,
		&lockedAt,
		&lockedBy,
		&scheduledFor,
		&item.CreatedAt,
		&item.UpdatedAt,
		&completedAt,
	); err != nil {
		return nil, err
	}
	applyComponentAnalysisQueueNulls(&item, lastError, lockedAt, lockedBy, scheduledFor, completedAt)
	return &item, nil
}

func scanComponentAnalysisQueueRow(rows *sql.Rows) (*models.ComponentAnalysisQueueItem, error) {
	var item models.ComponentAnalysisQueueItem
	var lastError sql.NullString
	var lockedAt sql.NullTime
	var lockedBy sql.NullString
	var scheduledFor sql.NullTime
	var completedAt sql.NullTime
	if err := rows.Scan(
		&item.ID,
		&item.ComponentPURL,
		&item.Status,
		&item.Reason,
		&item.Attempts,
		&lastError,
		&lockedAt,
		&lockedBy,
		&scheduledFor,
		&item.CreatedAt,
		&item.UpdatedAt,
		&completedAt,
	); err != nil {
		return nil, err
	}
	applyComponentAnalysisQueueNulls(&item, lastError, lockedAt, lockedBy, scheduledFor, completedAt)
	return &item, nil
}

func applyComponentAnalysisQueueNulls(
	item *models.ComponentAnalysisQueueItem,
	lastError sql.NullString,
	lockedAt sql.NullTime,
	lockedBy sql.NullString,
	scheduledFor sql.NullTime,
	completedAt sql.NullTime,
) {
	if item == nil {
		return
	}
	if lastError.Valid {
		item.LastError = lastError.String
	}
	if lockedAt.Valid {
		value := lockedAt.Time
		item.LockedAt = &value
	}
	if lockedBy.Valid {
		item.LockedBy = lockedBy.String
	}
	if scheduledFor.Valid {
		value := scheduledFor.Time
		item.ScheduledFor = &value
	}
	if completedAt.Valid {
		value := completedAt.Time
		item.CompletedAt = &value
	}
}

func scanComponentAnalysisFinding(row *sql.Row) (*models.ComponentAnalysisFinding, error) {
	var finding models.ComponentAnalysisFinding
	var triagePriority sql.NullString
	if err := row.Scan(
		&finding.ID,
		&finding.ComponentPURL,
		&finding.MalwarePURL,
		&finding.SourceMalwareInputResultID,
		&finding.MatchType,
		&finding.CreatedAt,
		&finding.UpdatedAt,
		&finding.TriageStatus,
		&triagePriority,
		&finding.EffectivePriority,
	); err != nil {
		return nil, err
	}
	if triagePriority.Valid {
		finding.TriagePriority = &triagePriority.String
	}
	return &finding, nil
}

func scanComponentAnalysisFindingRow(rows *sql.Rows) (*models.ComponentAnalysisFinding, error) {
	var finding models.ComponentAnalysisFinding
	var triagePriority sql.NullString
	if err := rows.Scan(
		&finding.ID,
		&finding.ComponentPURL,
		&finding.MalwarePURL,
		&finding.SourceMalwareInputResultID,
		&finding.MatchType,
		&finding.CreatedAt,
		&finding.UpdatedAt,
		&finding.TriageStatus,
		&triagePriority,
		&finding.EffectivePriority,
	); err != nil {
		return nil, err
	}
	if triagePriority.Valid {
		finding.TriagePriority = &triagePriority.String
	}
	return &finding, nil
}

func nullString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullTime(value sql.NullTime) sql.NullTime {
	if !value.Valid {
		return sql.NullTime{}
	}
	return value
}
