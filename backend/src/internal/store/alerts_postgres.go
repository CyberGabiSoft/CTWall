package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
)

const alertDispatchDefaultWindow = 72 * time.Hour

func (s *PostgresStore) ListAlertGroups(q AlertGroupsQuery) ([]models.AlertGroup, int, error) {
	if s == nil {
		return nil, 0, errors.New("store is nil")
	}
	if q.ProjectID == uuid.Nil {
		return nil, 0, ErrInvalidPayload
	}
	if shouldCloseStaleOpenMalwareGroups(q) {
		if err := s.closeStaleOpenMalwareAlertGroups(q.ProjectID); err != nil {
			return nil, 0, err
		}
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 100 {
		q.Limit = 100
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	orderBy := "last_seen_at DESC"
	if strings.EqualFold(strings.TrimSpace(q.OrderBySeen), "first_seen") {
		orderBy = "first_seen_at DESC"
	}

	args := []any{q.ProjectID}
	where := []string{"project_id = $1"}
	argN := 2

	if len(q.Severities) > 0 {
		placeholders := make([]string, 0, len(q.Severities))
		for _, sev := range q.Severities {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, string(sev))
			argN++
		}
		where = append(where, "severity IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(q.Categories) > 0 {
		placeholders := make([]string, 0, len(q.Categories))
		for _, cat := range q.Categories {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, string(cat))
			argN++
		}
		where = append(where, "category IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(q.Types) > 0 {
		placeholders := make([]string, 0, len(q.Types))
		for _, typ := range q.Types {
			typ = strings.TrimSpace(typ)
			if typ == "" {
				continue
			}
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, typ)
			argN++
		}
		if len(placeholders) > 0 {
			where = append(where, "type IN ("+strings.Join(placeholders, ",")+")")
		}
	}
	if len(q.Status) > 0 {
		placeholders := make([]string, 0, len(q.Status))
		for _, st := range q.Status {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, string(st))
			argN++
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ",")+")")
	}
	if q.From != nil {
		where = append(where, fmt.Sprintf("last_seen_at >= $%d", argN))
		args = append(args, q.From.UTC())
		argN++
	}
	if q.To != nil {
		where = append(where, fmt.Sprintf("last_seen_at <= $%d", argN))
		args = append(args, q.To.UTC())
		argN++
	}
	if strings.TrimSpace(q.Query) != "" {
		qq := "%" + strings.ToLower(strings.TrimSpace(q.Query)) + "%"
		where = append(where, fmt.Sprintf("(LOWER(title) LIKE $%d OR LOWER(COALESCE(entity_ref,'')) LIKE $%d OR LOWER(type) LIKE $%d OR LOWER(category) LIKE $%d)", argN, argN, argN, argN))
		args = append(args, qq)
		argN++
	}

	whereSQL := strings.Join(where, " AND ")

	ctx, cancel := s.ctx()
	defer cancel()

	// Total
	{
		countSQL := "SELECT COUNT(*) FROM alert_groups WHERE " + whereSQL
		var total int
		if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
			return nil, 0, err
		}

		// Items
		argsItems := append([]any{}, args...)
		argsItems = append(argsItems, q.Limit, q.Offset)
		itemsSQL := `
SELECT
  ag.id,
  ag.project_id,
  ag.severity,
  ag.category,
  ag.type,
  ag.status,
  ag.group_key,
  ag.title,
  ag.entity_ref,
  CASE
    WHEN ag.type = 'malware.detected' THEN COALESCE((
      SELECT COUNT(DISTINCT (t.id::text || '|' || c.purl || '|' || f.malware_purl))
      FROM test_revisions tr
      JOIN tests t ON t.id = tr.test_id
      JOIN scopes sc ON sc.id = t.scope_id
      JOIN products p ON p.id = sc.product_id
      JOIN components c ON c.revision_id = tr.id
      JOIN component_analysis_malware_findings f
        ON f.component_purl = c.purl
      JOIN source_malware_input_results sr
        ON sr.id = f.source_malware_input_result_id
      LEFT JOIN component_malware_findings_triage tri
        ON tri.project_id = p.project_id
       AND tri.test_id = t.id
       AND tri.component_purl = c.purl
       AND tri.malware_purl = f.malware_purl
      WHERE p.project_id = ag.project_id
        AND tr.is_active = TRUE
        AND sr.verdict = 'MALWARE'
        AND f.malware_purl = split_part(ag.group_key, '|malware_purl:', 2)
        AND (
          tri.status IS NULL
          OR tri.status = 'OPEN'
          OR (tri.status = 'RISK_ACCEPTED' AND tri.expires_at IS NOT NULL AND tri.expires_at <= NOW())
        )
        AND (
          (
            position('|dedup_on:test|' in ag.group_key) > 0
            AND t.id::text = split_part(split_part(ag.group_key, '|test_id:', 2), '|', 1)
          )
          OR (
            position('|dedup_on:scope|' in ag.group_key) > 0
            AND sc.id::text = split_part(split_part(ag.group_key, '|scope_id:', 2), '|', 1)
          )
          OR (
            position('|dedup_on:product|' in ag.group_key) > 0
            AND p.id::text = split_part(split_part(ag.group_key, '|product_id:', 2), '|', 1)
          )
          OR (
            position('|dedup_on:test|' in ag.group_key) = 0
            AND position('|dedup_on:scope|' in ag.group_key) = 0
            AND position('|dedup_on:product|' in ag.group_key) = 0
          )
        )
    ), 0)
    ELSE ag.occurrences
  END AS occurrences,
  ag.first_seen_at,
  ag.last_seen_at,
  ag.last_notified_at,
  ag.acknowledged_at,
  ag.acknowledged_by,
  ag.closed_at,
  ag.closed_by,
  ag.created_at,
  ag.updated_at
FROM (
  SELECT
    id, project_id, severity, category, type, status, group_key, title, entity_ref,
    occurrences, first_seen_at, last_seen_at, last_notified_at,
    acknowledged_at, acknowledged_by, closed_at, closed_by,
    created_at, updated_at
  FROM alert_groups
  WHERE ` + whereSQL + `
  ORDER BY ` + orderBy + `
  LIMIT $` + fmt.Sprintf("%d", argN) + ` OFFSET $` + fmt.Sprintf("%d", argN+1) + `
) ag
ORDER BY ` + orderBy

		rows, err := s.db.QueryContext(ctx, itemsSQL, argsItems...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()

		out := make([]models.AlertGroup, 0, q.Limit)
		for rows.Next() {
			var it models.AlertGroup
			if err := rows.Scan(
				&it.ID, &it.ProjectID, &it.Severity, &it.Category, &it.Type, &it.Status, &it.GroupKey, &it.Title, &it.EntityRef,
				&it.Occurrences, &it.FirstSeenAt, &it.LastSeenAt, &it.LastNotifiedAt,
				&it.AcknowledgedAt, &it.AcknowledgedBy, &it.ClosedAt, &it.ClosedBy,
				&it.CreatedAt, &it.UpdatedAt,
			); err != nil {
				return nil, 0, err
			}
			out = append(out, it)
		}
		if err := rows.Err(); err != nil {
			return nil, 0, err
		}
		return out, total, nil
	}
}

func shouldCloseStaleOpenMalwareGroups(q AlertGroupsQuery) bool {
	includesMalware := len(q.Types) == 0
	if !includesMalware {
		for _, typ := range q.Types {
			if strings.EqualFold(strings.TrimSpace(typ), "malware.detected") {
				includesMalware = true
				break
			}
		}
	}
	if !includesMalware {
		return false
	}

	if len(q.Status) == 0 {
		return true
	}
	for _, status := range q.Status {
		if status == AlertGroupStatusOpen {
			return true
		}
	}
	return false
}

func (s *PostgresStore) closeStaleOpenMalwareAlertGroups(projectID uuid.UUID) error {
	if s == nil {
		return errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	now := time.Now().UTC()
	expiresAt := now.Add(alertDispatchDefaultWindow)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	rows, err := tx.QueryContext(ctx, `
UPDATE alert_groups ag
SET status = 'CLOSED',
    closed_at = $2,
    updated_at = $2
WHERE ag.project_id = $1
  AND ag.type = 'malware.detected'
  AND ag.status = 'OPEN'
  AND NOT EXISTS (
    SELECT 1
    FROM test_revisions tr
    JOIN tests t ON t.id = tr.test_id
    JOIN scopes sc ON sc.id = t.scope_id
    JOIN products p ON p.id = sc.product_id
    JOIN components c ON c.revision_id = tr.id
    JOIN component_analysis_malware_findings f
      ON f.component_purl = c.purl
    JOIN source_malware_input_results sr
      ON sr.id = f.source_malware_input_result_id
    LEFT JOIN component_malware_findings_triage tri
      ON tri.project_id = p.project_id
     AND tri.test_id = t.id
     AND tri.component_purl = c.purl
     AND tri.malware_purl = f.malware_purl
    WHERE p.project_id = ag.project_id
      AND tr.is_active = TRUE
      AND sr.verdict = 'MALWARE'
      AND f.malware_purl = split_part(ag.group_key, '|malware_purl:', 2)
      AND (
        tri.status IS NULL
        OR tri.status = 'OPEN'
        OR (tri.status = 'RISK_ACCEPTED' AND tri.expires_at IS NOT NULL AND tri.expires_at <= NOW())
      )
      AND (
        (
          position('|dedup_on:test|' in ag.group_key) > 0
          AND t.id::text = split_part(split_part(ag.group_key, '|test_id:', 2), '|', 1)
        )
        OR (
          position('|dedup_on:scope|' in ag.group_key) > 0
          AND sc.id::text = split_part(split_part(ag.group_key, '|scope_id:', 2), '|', 1)
        )
        OR (
          position('|dedup_on:product|' in ag.group_key) > 0
          AND p.id::text = split_part(split_part(ag.group_key, '|product_id:', 2), '|', 1)
        )
        OR (
          position('|dedup_on:test|' in ag.group_key) = 0
          AND position('|dedup_on:scope|' in ag.group_key) = 0
          AND position('|dedup_on:product|' in ag.group_key) = 0
        )
      )
  )
RETURNING ag.id
`, projectID, now)
	if err != nil {
		return err
	}
	closedGroupIDs := make([]uuid.UUID, 0, 16)
	for rows.Next() {
		var groupID uuid.UUID
		if err := rows.Scan(&groupID); err != nil {
			return err
		}
		closedGroupIDs = append(closedGroupIDs, groupID)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, groupID := range closedGroupIDs {
		if err := s.enqueueAlertEventTx(
			tx,
			projectID,
			groupID,
			AlertDispatchEventStateResolve,
			json.RawMessage(`{"reason":"auto_close_zero_active_occurrences"}`),
			&expiresAt,
		); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) GetAlertGroup(projectID, id uuid.UUID) (*models.AlertGroup, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || id == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
SELECT
  id, project_id, severity, category, type, status, group_key, title, entity_ref,
  occurrences, first_seen_at, last_seen_at, last_notified_at,
  acknowledged_at, acknowledged_by, closed_at, closed_by,
  created_at, updated_at
FROM alert_groups
WHERE project_id = $1 AND id = $2
`, projectID, id)
	var it models.AlertGroup
	if err := row.Scan(
		&it.ID, &it.ProjectID, &it.Severity, &it.Category, &it.Type, &it.Status, &it.GroupKey, &it.Title, &it.EntityRef,
		&it.Occurrences, &it.FirstSeenAt, &it.LastSeenAt, &it.LastNotifiedAt,
		&it.AcknowledgedAt, &it.AcknowledgedBy, &it.ClosedAt, &it.ClosedBy,
		&it.CreatedAt, &it.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &it, nil
}

func (s *PostgresStore) ListOpenAlertGroupsForHeartbeat(limit int, olderThan time.Duration) ([]models.AlertGroup, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if limit <= 0 {
		return nil, ErrInvalidPayload
	}
	if olderThan <= 0 {
		return nil, ErrInvalidPayload
	}
	seconds := int(olderThan.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
SELECT
  id, project_id, severity, category, type, status, group_key, title, entity_ref,
  occurrences, first_seen_at, last_seen_at, last_notified_at,
  acknowledged_at, acknowledged_by, closed_at, closed_by,
  created_at, updated_at
FROM alert_groups
WHERE status = 'OPEN'
  AND (
    last_notified_at IS NULL
    OR last_notified_at <= NOW() - ($1 * interval '1 second')
  )
ORDER BY COALESCE(last_notified_at, TIMESTAMPTZ '1970-01-01') ASC, last_seen_at ASC
LIMIT $2
`, seconds, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]models.AlertGroup, 0, limit)
	for rows.Next() {
		var it models.AlertGroup
		if err := rows.Scan(
			&it.ID, &it.ProjectID, &it.Severity, &it.Category, &it.Type, &it.Status, &it.GroupKey, &it.Title, &it.EntityRef,
			&it.Occurrences, &it.FirstSeenAt, &it.LastSeenAt, &it.LastNotifiedAt,
			&it.AcknowledgedAt, &it.AcknowledgedBy, &it.ClosedAt, &it.ClosedBy,
			&it.CreatedAt, &it.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) AcknowledgeAlertGroup(projectID, groupID, actorID uuid.UUID) error {
	return s.updateAlertGroupStatus(projectID, groupID, actorID, AlertGroupStatusAcknowledged)
}

func (s *PostgresStore) CloseAlertGroup(projectID, groupID, actorID uuid.UUID) error {
	return s.updateAlertGroupStatus(projectID, groupID, actorID, AlertGroupStatusClosed)
}

func (s *PostgresStore) updateAlertGroupStatus(projectID, groupID, actorID uuid.UUID, status AlertGroupStatus) error {
	if s == nil {
		return errors.New("store is nil")
	}
	if projectID == uuid.Nil || groupID == uuid.Nil || actorID == uuid.Nil {
		return ErrInvalidPayload
	}
	if status != AlertGroupStatusAcknowledged && status != AlertGroupStatusClosed {
		return ErrInvalidPayload
	}
	now := time.Now().UTC()
	expiresAt := now.Add(alertDispatchDefaultWindow)

	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var sqlText string
	switch status {
	case AlertGroupStatusAcknowledged:
		sqlText = `
UPDATE alert_groups
SET status = 'ACKNOWLEDGED',
    acknowledged_at = $3,
    acknowledged_by = $4,
    updated_at = $3
WHERE project_id = $1 AND id = $2`
	case AlertGroupStatusClosed:
		sqlText = `
UPDATE alert_groups
SET status = 'CLOSED',
    closed_at = $3,
    closed_by = $4,
    updated_at = $3
	WHERE project_id = $1 AND id = $2`
	}
	res, err := tx.ExecContext(ctx, sqlText, projectID, groupID, now, actorID)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrNotFound
	}
	if status == AlertGroupStatusClosed {
		state := AlertDispatchEventStateResolve
		if err := s.enqueueAlertEventTx(tx, projectID, groupID, state, json.RawMessage(`{"reason":"group_closed"}`), &expiresAt); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ListAlertOccurrences(q AlertOccurrencesQuery) ([]models.AlertOccurrence, int, error) {
	if s == nil {
		return nil, 0, errors.New("store is nil")
	}
	if q.ProjectID == uuid.Nil {
		return nil, 0, ErrInvalidPayload
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 200 {
		q.Limit = 200
	}
	if q.Offset < 0 {
		q.Offset = 0
	}

	args := []any{q.ProjectID}
	where := []string{"o.project_id = $1"}
	argN := 2

	if q.GroupID != nil && *q.GroupID != uuid.Nil {
		where = append(where, fmt.Sprintf("o.group_id = $%d", argN))
		args = append(args, *q.GroupID)
		argN++
	}
	if q.From != nil {
		where = append(where, fmt.Sprintf("o.occurred_at >= $%d", argN))
		args = append(args, q.From.UTC())
		argN++
	}
	if q.To != nil {
		where = append(where, fmt.Sprintf("o.occurred_at <= $%d", argN))
		args = append(args, q.To.UTC())
		argN++
	}
	if strings.TrimSpace(q.Query) != "" {
		qq := "%" + strings.ToLower(strings.TrimSpace(q.Query)) + "%"
		where = append(where, fmt.Sprintf("(LOWER(COALESCE(o.entity_ref,'')) LIKE $%d OR LOWER(COALESCE(g.title,'')) LIKE $%d OR LOWER(COALESCE(g.type,'')) LIKE $%d)", argN, argN, argN))
		args = append(args, qq)
		argN++
	}
	if len(q.Severities) > 0 {
		placeholders := make([]string, 0, len(q.Severities))
		for _, sev := range q.Severities {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, string(sev))
			argN++
		}
		where = append(where, "g.severity IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(q.Categories) > 0 {
		placeholders := make([]string, 0, len(q.Categories))
		for _, cat := range q.Categories {
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, string(cat))
			argN++
		}
		where = append(where, "g.category IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(q.Types) > 0 {
		placeholders := make([]string, 0, len(q.Types))
		for _, typ := range q.Types {
			typ = strings.TrimSpace(typ)
			if typ == "" {
				continue
			}
			placeholders = append(placeholders, fmt.Sprintf("$%d", argN))
			args = append(args, typ)
			argN++
		}
		if len(placeholders) > 0 {
			where = append(where, "g.type IN ("+strings.Join(placeholders, ",")+")")
		}
	}

	whereSQL := strings.Join(where, " AND ")

	ctx, cancel := s.ctx()
	defer cancel()

	countSQL := `
SELECT COUNT(*)
FROM alert_occurrences o
JOIN alert_groups g ON g.id = o.group_id
WHERE ` + whereSQL
	var total int
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	argsItems := append([]any{}, args...)
	argsItems = append(argsItems, q.Limit, q.Offset)
	itemsSQL := `
SELECT
  o.id, o.project_id, o.group_id,
  g.severity, g.category, g.type, g.title,
  o.occurred_at, o.product_id, o.scope_id, o.test_id,
  o.entity_ref, o.details, o.created_at
FROM alert_occurrences o
JOIN alert_groups g ON g.id = o.group_id
WHERE ` + whereSQL + `
ORDER BY o.occurred_at DESC
LIMIT $` + fmt.Sprintf("%d", argN) + ` OFFSET $` + fmt.Sprintf("%d", argN+1)

	rows, err := s.db.QueryContext(ctx, itemsSQL, argsItems...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]models.AlertOccurrence, 0, q.Limit)
	for rows.Next() {
		var it models.AlertOccurrence
		if err := rows.Scan(
			&it.ID, &it.ProjectID, &it.GroupID,
			&it.Severity, &it.Category, &it.Type, &it.Title,
			&it.OccurredAt,
			&it.ProductID, &it.ScopeID, &it.TestID,
			&it.EntityRef, &it.Details, &it.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// UpsertAlertGroupAndInsertOccurrence upserts a group (dedupe) and inserts an occurrence in a single transaction.
func (s *PostgresStore) UpsertAlertGroupAndInsertOccurrence(group AlertGroupUpsert, occ AlertOccurrenceInsert) (*models.AlertGroup, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if group.ProjectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if !eventmeta.ValidSeverity(string(group.Severity)) || !eventmeta.ValidCategory(string(group.Category)) {
		return nil, ErrInvalidPayload
	}
	group.Type = strings.TrimSpace(group.Type)
	group.GroupKey = strings.TrimSpace(group.GroupKey)
	group.Title = strings.TrimSpace(group.Title)
	if group.Type == "" || group.GroupKey == "" || group.Title == "" {
		return nil, ErrInvalidPayload
	}
	if occ.Details == nil {
		occ.Details = json.RawMessage(`{}`)
	}
	if !json.Valid(occ.Details) {
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

	now := time.Now().UTC()
	var groupID uuid.UUID
	// UPSERT group with reopen semantics.
	err = tx.QueryRowContext(ctx, `
INSERT INTO alert_groups (
  project_id, severity, category, type, status, group_key, title, entity_ref,
  occurrences, first_seen_at, last_seen_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, 'OPEN', $5, $6, $7, 1, $8, $8, $8, $8)
ON CONFLICT (project_id, group_key) DO UPDATE
SET occurrences = alert_groups.occurrences + 1,
    last_seen_at = EXCLUDED.last_seen_at,
    updated_at = EXCLUDED.updated_at,
    -- Re-open when new occurrence arrives after ack/close.
    status = CASE WHEN alert_groups.status IN ('ACKNOWLEDGED','CLOSED') THEN 'OPEN' ELSE alert_groups.status END,
    acknowledged_at = CASE WHEN alert_groups.status IN ('ACKNOWLEDGED','CLOSED') THEN NULL ELSE alert_groups.acknowledged_at END,
    acknowledged_by = CASE WHEN alert_groups.status IN ('ACKNOWLEDGED','CLOSED') THEN NULL ELSE alert_groups.acknowledged_by END,
    closed_at = CASE WHEN alert_groups.status IN ('ACKNOWLEDGED','CLOSED') THEN NULL ELSE alert_groups.closed_at END,
    closed_by = CASE WHEN alert_groups.status IN ('ACKNOWLEDGED','CLOSED') THEN NULL ELSE alert_groups.closed_by END
RETURNING id
`, group.ProjectID, string(group.Severity), string(group.Category), group.Type, group.GroupKey, group.Title, group.EntityRef, now).Scan(&groupID)
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrInvalidPayload
		}
		return nil, err
	}

	occurredAt := now
	if occ.OccurredAt != nil {
		occurredAt = occ.OccurredAt.UTC()
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_occurrences (
  project_id, group_id, occurred_at, product_id, scope_id, test_id, entity_ref, details, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, group.ProjectID, groupID, occurredAt, occ.ProductID, occ.ScopeID, occ.TestID, occ.EntityRef, occ.Details, now); err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrInvalidPayload
		}
		return nil, err
	}
	expiresAt := now.Add(alertDispatchDefaultWindow)
	if err := s.enqueueAlertEventTx(tx, group.ProjectID, groupID, AlertDispatchEventStateFiring, json.RawMessage(`{"reason":"occurrence_upsert"}`), &expiresAt); err != nil {
		return nil, err
	}

	var out models.AlertGroup
	row := tx.QueryRowContext(ctx, `
SELECT
  id, project_id, severity, category, type, status, group_key, title, entity_ref,
  occurrences, first_seen_at, last_seen_at, last_notified_at,
  acknowledged_at, acknowledged_by, closed_at, closed_by,
  created_at, updated_at
FROM alert_groups
WHERE project_id = $1 AND id = $2
`, group.ProjectID, groupID)
	if err := row.Scan(
		&out.ID, &out.ProjectID, &out.Severity, &out.Category, &out.Type, &out.Status, &out.GroupKey, &out.Title, &out.EntityRef,
		&out.Occurrences, &out.FirstSeenAt, &out.LastSeenAt, &out.LastNotifiedAt,
		&out.AcknowledgedAt, &out.AcknowledgedBy, &out.ClosedAt, &out.ClosedBy,
		&out.CreatedAt, &out.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}
