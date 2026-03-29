package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
)

const (
	reimportAutoCloseReason  = "Finding removed after SBOM reimport."
	reimportAutoReopenReason = "Finding re-detected after SBOM reimport."
	reimportAuditComponent   = "store.test_revision_finding_diffs"
)

type revisionDiffContext struct {
	projectID      uuid.UUID
	testID         uuid.UUID
	fromRevisionID *uuid.UUID
	toRevisionID   uuid.UUID
}

type revisionFindingKey struct {
	componentPURL string
	malwarePURL   string
}

type revisionFindingDiffEntry struct {
	diffType      string
	componentPURL string
	malwarePURL   string
}

type revisionDiffCounts struct {
	added      int
	removed    int
	unchanged  int
	reappeared int
}

func (s *PostgresStore) EnqueueTestRevisionFindingDiff(toRevisionID uuid.UUID, reason string) (*models.TestRevisionFindingDiffQueueItem, error) {
	if toRevisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if !isValidTestRevisionFindingDiffReason(reason) {
		return nil, ErrInvalidPayload
	}
	normalizedReason := normalizeTestRevisionFindingDiffReason(reason)

	ctx, cancel := s.ctx()
	defer cancel()

	diffCtx, err := s.loadRevisionDiffContext(ctx, toRevisionID)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	fromRevisionValue := nullableUUID(diffCtx.fromRevisionID)
	if _, err := tx.ExecContext(ctx, `
INSERT INTO test_revision_change_summary (
  to_revision_id, project_id, test_id, from_revision_id,
  added_count, removed_count, unchanged_count, reappeared_count,
  status, computed_at, updated_at
)
VALUES ($1, $2, $3, $4, 0, 0, 0, 0, $5, NULL, NOW())
ON CONFLICT (to_revision_id) DO UPDATE
SET project_id = EXCLUDED.project_id,
    test_id = EXCLUDED.test_id,
    from_revision_id = EXCLUDED.from_revision_id,
    added_count = 0,
    removed_count = 0,
    unchanged_count = 0,
    reappeared_count = 0,
    status = EXCLUDED.status,
    computed_at = NULL,
    updated_at = NOW()
`, diffCtx.toRevisionID, diffCtx.projectID, diffCtx.testID, fromRevisionValue, TestRevisionFindingDiffStatusPending); err != nil {
		return nil, err
	}

	row := tx.QueryRowContext(ctx, `
INSERT INTO test_revision_finding_diff_queue (
  project_id, test_id, from_revision_id, to_revision_id, status, reason
)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (to_revision_id) DO UPDATE
SET project_id = EXCLUDED.project_id,
    test_id = EXCLUDED.test_id,
    from_revision_id = EXCLUDED.from_revision_id,
    status = EXCLUDED.status,
    reason = EXCLUDED.reason,
    last_error = NULL,
    completed_at = NULL,
    updated_at = NOW()
RETURNING id, project_id, test_id, from_revision_id::text, to_revision_id, status, reason, attempts, last_error, locked_at, locked_by, created_at, updated_at, completed_at
`, diffCtx.projectID, diffCtx.testID, fromRevisionValue, diffCtx.toRevisionID, TestRevisionFindingDiffStatusPending, normalizedReason)

	item, err := scanTestRevisionFindingDiffQueueItem(row)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	actorID, actorErr := s.ensureSystemActorID(ctx)
	if actorErr != nil {
		slog.Error("ensure system actor failed", "component", reimportAuditComponent, "error", actorErr)
	} else {
		s.writeReimportAuditEvent(reimportAuditEventInput{
			actorID:        actorID,
			action:         "MALWARE_REIMPORT_DIFF_JOB_ENQUEUED",
			entityType:     "test_revision",
			entityID:       &diffCtx.toRevisionID,
			eventKey:       "malware.reimport_diff_job_enqueued",
			severity:       eventmeta.SeverityInfo,
			title:          "SBOM reimport diff job enqueued",
			projectID:      diffCtx.projectID,
			testID:         diffCtx.testID,
			fromRevisionID: diffCtx.fromRevisionID,
			toRevisionID:   diffCtx.toRevisionID,
			extra: map[string]any{
				"reason": normalizedReason,
			},
		})
	}

	return item, nil
}

func (s *PostgresStore) ClaimTestRevisionFindingDiffJobs(limit int, lockedBy string) ([]models.TestRevisionFindingDiffQueueItem, error) {
	if limit <= 0 {
		return nil, ErrInvalidPayload
	}
	lockedBy = strings.TrimSpace(lockedBy)
	if lockedBy == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
WITH next_jobs AS (
  SELECT id
  FROM test_revision_finding_diff_queue
  WHERE status = $1
  ORDER BY updated_at
  FOR UPDATE SKIP LOCKED
  LIMIT $2
)
UPDATE test_revision_finding_diff_queue q
SET status = $3,
    attempts = q.attempts + 1,
    locked_at = NOW(),
    locked_by = $4,
    updated_at = NOW()
FROM next_jobs
WHERE q.id = next_jobs.id
RETURNING q.id, q.project_id, q.test_id, q.from_revision_id::text, q.to_revision_id, q.status, q.reason, q.attempts, q.last_error, q.locked_at, q.locked_by, q.created_at, q.updated_at, q.completed_at
`, TestRevisionFindingDiffStatusPending, limit, TestRevisionFindingDiffStatusProcessing, lockedBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.TestRevisionFindingDiffQueueItem, 0)
	for rows.Next() {
		item, err := scanTestRevisionFindingDiffQueueRow(rows)
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

func (s *PostgresStore) UpdateTestRevisionFindingDiffQueueStatus(id uuid.UUID, status, lastError string) error {
	if id == uuid.Nil {
		return ErrInvalidPayload
	}
	if !isValidTestRevisionFindingDiffStatus(status) {
		return ErrInvalidPayload
	}
	normalized := normalizeTestRevisionFindingDiffStatus(status)
	lastError = strings.TrimSpace(lastError)

	ctx, cancel := s.ctx()
	defer cancel()

	var current string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status FROM test_revision_finding_diff_queue WHERE id = $1`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !testRevisionFindingDiffState.CanTransition(current, normalized) {
		return ErrInvalidStateTransition
	}

	completedAt := sql.NullTime{}
	if normalized == TestRevisionFindingDiffStatusCompleted || normalized == TestRevisionFindingDiffStatusFailed {
		completedAt = sql.NullTime{Valid: true, Time: time.Now().UTC()}
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE test_revision_finding_diff_queue
SET status = $1,
    last_error = $2,
    completed_at = $3,
    updated_at = NOW()
WHERE id = $4
`, normalized, nullString(lastError), nullTime(completedAt), id)
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

func (s *PostgresStore) ComputeAndStoreTestRevisionFindingDiff(toRevisionID uuid.UUID) (*models.TestRevisionChangeSummary, error) {
	if toRevisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	diffCtx, err := s.loadRevisionDiffContext(ctx, toRevisionID)
	if err != nil {
		return nil, err
	}

	fromPairs, err := s.loadRevisionMalwarePairs(ctx, diffCtx.fromRevisionID)
	if err != nil {
		return nil, err
	}
	toPairs, err := s.loadRevisionMalwarePairs(ctx, &toRevisionID)
	if err != nil {
		return nil, err
	}
	closedPairs, err := s.loadClosedTriagePairs(ctx, diffCtx.projectID, diffCtx.testID)
	if err != nil {
		return nil, err
	}

	entries, counts := buildRevisionFindingDiffEntries(fromPairs, toPairs, closedPairs)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
DELETE FROM test_revision_finding_diffs
WHERE to_revision_id = $1
  AND finding_type = $2
`, toRevisionID, TestRevisionFindingTypeMalware); err != nil {
		return nil, err
	}

	if err := insertRevisionFindingDiffEntriesTx(ctx, tx, diffCtx, entries); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO test_revision_change_summary (
  to_revision_id, project_id, test_id, from_revision_id,
  added_count, removed_count, unchanged_count, reappeared_count,
  status, computed_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NOW())
ON CONFLICT (to_revision_id) DO UPDATE
SET project_id = EXCLUDED.project_id,
    test_id = EXCLUDED.test_id,
    from_revision_id = EXCLUDED.from_revision_id,
    added_count = EXCLUDED.added_count,
    removed_count = EXCLUDED.removed_count,
    unchanged_count = EXCLUDED.unchanged_count,
    reappeared_count = EXCLUDED.reappeared_count,
    status = EXCLUDED.status,
    computed_at = NULL,
    updated_at = NOW()
`, toRevisionID, diffCtx.projectID, diffCtx.testID, nullableUUID(diffCtx.fromRevisionID), counts.added, counts.removed, counts.unchanged, counts.reappeared, TestRevisionFindingDiffStatusProcessing); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	systemActorID, actorErr := s.ensureSystemActorID(ctx)
	if actorErr != nil {
		_ = s.updateTestRevisionChangeSummaryStatus(toRevisionID, TestRevisionFindingDiffStatusFailed, false)
		return nil, actorErr
	}

	if err := s.applyRevisionFindingDiffSideEffects(ctx, diffCtx, entries, systemActorID); err != nil {
		_ = s.updateTestRevisionChangeSummaryStatus(toRevisionID, TestRevisionFindingDiffStatusFailed, false)
		s.writeReimportAuditEvent(reimportAuditEventInput{
			actorID:        systemActorID,
			action:         "MALWARE_REIMPORT_DIFF_FAILED",
			entityType:     "test_revision",
			entityID:       &toRevisionID,
			eventKey:       "malware.reimport_diff_failed",
			severity:       eventmeta.SeverityError,
			title:          "SBOM reimport diff computation failed",
			projectID:      diffCtx.projectID,
			testID:         diffCtx.testID,
			fromRevisionID: diffCtx.fromRevisionID,
			toRevisionID:   toRevisionID,
			extra: map[string]any{
				"error": strings.TrimSpace(err.Error()),
			},
		})
		return nil, err
	}

	if err := s.updateTestRevisionChangeSummaryStatus(toRevisionID, TestRevisionFindingDiffStatusCompleted, true); err != nil {
		return nil, err
	}

	summary, err := s.GetTestRevisionChangeSummary(diffCtx.testID, toRevisionID)
	if err != nil {
		return nil, err
	}

	s.writeReimportAuditEvent(reimportAuditEventInput{
		actorID:        systemActorID,
		action:         "MALWARE_REIMPORT_DIFF_COMPUTED",
		entityType:     "test_revision",
		entityID:       &toRevisionID,
		eventKey:       "malware.reimport_diff_computed",
		severity:       eventmeta.SeverityInfo,
		title:          "SBOM reimport diff computed",
		projectID:      diffCtx.projectID,
		testID:         diffCtx.testID,
		fromRevisionID: diffCtx.fromRevisionID,
		toRevisionID:   toRevisionID,
		extra: map[string]any{
			"addedCount":      summary.AddedCount,
			"removedCount":    summary.RemovedCount,
			"unchangedCount":  summary.UnchangedCount,
			"reappearedCount": summary.ReappearedCount,
		},
	})

	return summary, nil
}

func (s *PostgresStore) ListTestRevisionLastChanges(testID uuid.UUID) ([]models.TestRevisionChangeSummary, error) {
	if testID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT to_revision_id, project_id, test_id, from_revision_id::text,
       added_count, removed_count, unchanged_count, reappeared_count,
       status, computed_at, created_at, updated_at
FROM test_revision_change_summary
WHERE test_id = $1
ORDER BY created_at DESC
`, testID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.TestRevisionChangeSummary, 0)
	for rows.Next() {
		item, err := scanTestRevisionChangeSummaryRow(rows)
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

func (s *PostgresStore) GetTestRevisionChangeSummary(testID, revisionID uuid.UUID) (*models.TestRevisionChangeSummary, error) {
	if testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx, `
SELECT to_revision_id, project_id, test_id, from_revision_id::text,
       added_count, removed_count, unchanged_count, reappeared_count,
       status, computed_at, created_at, updated_at
FROM test_revision_change_summary
WHERE test_id = $1
  AND to_revision_id = $2
`, testID, revisionID)
	item, err := scanTestRevisionChangeSummary(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) ListTestRevisionFindingDiffs(testID, revisionID uuid.UUID, diffTypes []string) ([]models.TestRevisionFindingDiff, error) {
	if testID == uuid.Nil || revisionID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	normalizedTypes := normalizeAndValidateDiffTypes(diffTypes)
	if normalizedTypes == nil {
		return nil, ErrInvalidPayload
	}

	args := []any{testID, revisionID}
	where := []string{"test_id = $1", "to_revision_id = $2"}
	argN := 3
	if len(normalizedTypes) > 0 {
		placeholders := make([]string, 0, len(normalizedTypes))
		for _, diffType := range normalizedTypes {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, diffType)
			argN++
		}
		where = append(where, "diff_type IN ("+strings.Join(placeholders, ",")+")")
	}

	query := `
SELECT id, project_id, test_id, from_revision_id::text, to_revision_id, finding_type, diff_type, component_purl, malware_purl, created_at
FROM test_revision_finding_diffs
WHERE ` + strings.Join(where, " AND ") + `
ORDER BY created_at DESC, component_purl ASC, malware_purl ASC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.TestRevisionFindingDiff, 0)
	for rows.Next() {
		item, err := scanTestRevisionFindingDiffRow(rows)
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

func (s *PostgresStore) loadRevisionDiffContext(ctx context.Context, toRevisionID uuid.UUID) (*revisionDiffContext, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT p.project_id,
       tr.test_id,
       (
         SELECT prev.id::text
         FROM test_revisions prev
         WHERE prev.test_id = tr.test_id
           AND prev.id <> tr.id
         ORDER BY prev.created_at DESC, prev.id DESC
         LIMIT 1
       ) AS from_revision_id
FROM test_revisions tr
JOIN tests t ON t.id = tr.test_id
JOIN scopes sc ON sc.id = t.scope_id
JOIN products p ON p.id = sc.product_id
WHERE tr.id = $1
`, toRevisionID)
	var ctxOut revisionDiffContext
	var fromRevisionID sql.NullString
	if err := row.Scan(&ctxOut.projectID, &ctxOut.testID, &fromRevisionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	ctxOut.toRevisionID = toRevisionID
	if fromRevisionID.Valid {
		id, parseErr := uuid.Parse(strings.TrimSpace(fromRevisionID.String))
		if parseErr == nil && id != uuid.Nil {
			ctxOut.fromRevisionID = &id
		}
	}
	return &ctxOut, nil
}

func (s *PostgresStore) loadRevisionMalwarePairs(ctx context.Context, revisionID *uuid.UUID) (map[revisionFindingKey]struct{}, error) {
	out := make(map[revisionFindingKey]struct{})
	if revisionID == nil || *revisionID == uuid.Nil {
		return out, nil
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT c.purl, f.malware_purl
FROM components c
JOIN component_analysis_malware_findings f
  ON f.component_purl = c.purl
JOIN source_malware_input_results r
  ON r.id = f.source_malware_input_result_id
WHERE c.revision_id = $1
  AND r.verdict = 'MALWARE'
`, *revisionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var componentPURL string
		var malwarePURL string
		if err := rows.Scan(&componentPURL, &malwarePURL); err != nil {
			return nil, err
		}
		componentPURL = strings.TrimSpace(componentPURL)
		malwarePURL = strings.TrimSpace(malwarePURL)
		if componentPURL == "" || malwarePURL == "" {
			continue
		}
		out[revisionFindingKey{componentPURL: componentPURL, malwarePURL: malwarePURL}] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) loadClosedTriagePairs(ctx context.Context, projectID, testID uuid.UUID) (map[revisionFindingKey]struct{}, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT component_purl, malware_purl
FROM component_malware_findings_triage
WHERE project_id = $1
  AND test_id = $2
  AND status <> 'OPEN'
`, projectID, testID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[revisionFindingKey]struct{})
	for rows.Next() {
		var componentPURL string
		var malwarePURL string
		if err := rows.Scan(&componentPURL, &malwarePURL); err != nil {
			return nil, err
		}
		componentPURL = strings.TrimSpace(componentPURL)
		malwarePURL = strings.TrimSpace(malwarePURL)
		if componentPURL == "" || malwarePURL == "" {
			continue
		}
		out[revisionFindingKey{componentPURL: componentPURL, malwarePURL: malwarePURL}] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func buildRevisionFindingDiffEntries(
	fromPairs map[revisionFindingKey]struct{},
	toPairs map[revisionFindingKey]struct{},
	closedPairs map[revisionFindingKey]struct{},
) ([]revisionFindingDiffEntry, revisionDiffCounts) {
	entries := make([]revisionFindingDiffEntry, 0, len(fromPairs)+len(toPairs))
	counts := revisionDiffCounts{}

	for key := range toPairs {
		if _, exists := fromPairs[key]; exists {
			if _, wasClosed := closedPairs[key]; wasClosed {
				entries = append(entries, revisionFindingDiffEntry{
					diffType:      TestRevisionFindingDiffTypeReappeared,
					componentPURL: key.componentPURL,
					malwarePURL:   key.malwarePURL,
				})
				counts.reappeared++
				continue
			}
			entries = append(entries, revisionFindingDiffEntry{
				diffType:      TestRevisionFindingDiffTypeUnchanged,
				componentPURL: key.componentPURL,
				malwarePURL:   key.malwarePURL,
			})
			counts.unchanged++
			continue
		}
		diffType := TestRevisionFindingDiffTypeAdded
		if _, wasClosed := closedPairs[key]; wasClosed {
			diffType = TestRevisionFindingDiffTypeReappeared
			counts.reappeared++
		} else {
			counts.added++
		}
		entries = append(entries, revisionFindingDiffEntry{
			diffType:      diffType,
			componentPURL: key.componentPURL,
			malwarePURL:   key.malwarePURL,
		})
	}

	for key := range fromPairs {
		if _, exists := toPairs[key]; exists {
			continue
		}
		entries = append(entries, revisionFindingDiffEntry{
			diffType:      TestRevisionFindingDiffTypeRemoved,
			componentPURL: key.componentPURL,
			malwarePURL:   key.malwarePURL,
		})
		counts.removed++
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].diffType != entries[j].diffType {
			return entries[i].diffType < entries[j].diffType
		}
		if entries[i].componentPURL != entries[j].componentPURL {
			return entries[i].componentPURL < entries[j].componentPURL
		}
		return entries[i].malwarePURL < entries[j].malwarePURL
	})

	return entries, counts
}

func insertRevisionFindingDiffEntriesTx(ctx context.Context, tx *sql.Tx, diffCtx *revisionDiffContext, entries []revisionFindingDiffEntry) error {
	if len(entries) == 0 {
		return nil
	}
	var builder strings.Builder
	builder.WriteString(`
INSERT INTO test_revision_finding_diffs (
  project_id, test_id, from_revision_id, to_revision_id, finding_type, diff_type, component_purl, malware_purl
) VALUES `)

	args := make([]any, 0, len(entries)*8)
	argN := 1
	fromRevisionValue := nullableUUID(diffCtx.fromRevisionID)
	for idx, entry := range entries {
		if idx > 0 {
			builder.WriteString(",")
		}
		builder.WriteString(fmt.Sprintf(" ($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", argN, argN+1, argN+2, argN+3, argN+4, argN+5, argN+6, argN+7))
		args = append(args,
			diffCtx.projectID,
			diffCtx.testID,
			fromRevisionValue,
			diffCtx.toRevisionID,
			TestRevisionFindingTypeMalware,
			entry.diffType,
			entry.componentPURL,
			entry.malwarePURL,
		)
		argN += 8
	}

	if _, err := tx.ExecContext(ctx, builder.String(), args...); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) applyRevisionFindingDiffSideEffects(
	ctx context.Context,
	diffCtx *revisionDiffContext,
	entries []revisionFindingDiffEntry,
	systemActorID *uuid.UUID,
) error {
	removedMalware := make(map[string]struct{})
	summaryNeedsRecompute := false
	for _, entry := range entries {
		switch entry.diffType {
		case TestRevisionFindingDiffTypeAdded, TestRevisionFindingDiffTypeReappeared:
			_, err := s.UpsertComponentMalwareFindingTriage(
				diffCtx.projectID,
				diffCtx.testID,
				entry.componentPURL,
				entry.malwarePURL,
				string(MalwareFindingTriageStatusOpen),
				nil,
				ptrString(reimportAutoReopenReason),
				nil,
				systemActorID,
			)
			if err != nil {
				return err
			}
			if _, err := s.CreateMalwareDetectedAlertOccurrences(entry.componentPURL, entry.malwarePURL); err != nil {
				return err
			}
			summaryNeedsRecompute = true
		case TestRevisionFindingDiffTypeRemoved:
			_, err := s.UpsertComponentMalwareFindingTriage(
				diffCtx.projectID,
				diffCtx.testID,
				entry.componentPURL,
				entry.malwarePURL,
				string(MalwareFindingTriageStatusFixed),
				nil,
				ptrString(reimportAutoCloseReason),
				nil,
				systemActorID,
			)
			if err != nil {
				return err
			}
			removedMalware[entry.malwarePURL] = struct{}{}
			summaryNeedsRecompute = true

			s.writeReimportAuditEvent(reimportAuditEventInput{
				actorID:        systemActorID,
				action:         "MALWARE_FINDING_AUTO_CLOSED_REIMPORT_REMOVED",
				entityType:     "malware_finding",
				entityID:       nil,
				eventKey:       "malware.finding_auto_closed_reimport_removed",
				severity:       eventmeta.SeverityInfo,
				title:          "Malware finding auto-fixed after reimport removal",
				projectID:      diffCtx.projectID,
				testID:         diffCtx.testID,
				fromRevisionID: diffCtx.fromRevisionID,
				toRevisionID:   diffCtx.toRevisionID,
				extra: map[string]any{
					"componentPurl": entry.componentPURL,
					"malwarePurl":   entry.malwarePURL,
					"reason":        reimportAutoCloseReason,
				},
			})
		}
	}

	for malwarePURL := range removedMalware {
		if err := s.ReconcileMalwareAlertGroup(diffCtx.projectID, malwarePURL, systemActorID); err != nil {
			return err
		}
	}

	// Recompute summary after triage/alert side effects.
	// Without this, summary can stay stale when diff processing reopens FIXED findings.
	if summaryNeedsRecompute && diffCtx.toRevisionID != uuid.Nil {
		if _, err := s.ComputeAndStoreTestRevisionMalwareSummary(diffCtx.toRevisionID); err != nil {
			return err
		}
	}

	_ = ctx
	return nil
}

func (s *PostgresStore) updateTestRevisionChangeSummaryStatus(toRevisionID uuid.UUID, status string, computed bool) error {
	ctx, cancel := s.ctx()
	defer cancel()

	if !isValidTestRevisionFindingDiffStatus(status) {
		return ErrInvalidPayload
	}
	normalizedStatus := normalizeTestRevisionFindingDiffStatus(status)

	var computedAt any
	if computed {
		computedAt = time.Now().UTC()
	} else {
		computedAt = nil
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE test_revision_change_summary
SET status = $2,
    computed_at = $3,
    updated_at = NOW()
WHERE to_revision_id = $1
`, toRevisionID, normalizedStatus, computedAt)
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

func normalizeAndValidateDiffTypes(diffTypes []string) []string {
	if len(diffTypes) == 0 {
		return []string{}
	}
	uniq := make(map[string]struct{}, len(diffTypes))
	for _, raw := range diffTypes {
		value := normalizeTestRevisionFindingDiffType(raw)
		if value == "" {
			continue
		}
		if !isValidTestRevisionFindingDiffType(value) {
			return nil
		}
		uniq[value] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for value := range uniq {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
