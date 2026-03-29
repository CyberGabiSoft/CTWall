package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

func scanAlertDispatchJobRow(scanner interface {
	Scan(dest ...any) error
}) (*AlertDispatchJob, error) {
	var item AlertDispatchJob
	var eventState sql.NullString
	var projectID uuid.NullUUID
	var groupID uuid.NullUUID
	var expiresAt sql.NullTime
	var lockedAt sql.NullTime
	var lockedBy sql.NullString
	var lastErrorCode sql.NullString
	var lastErrorMessage sql.NullString
	var doneAt sql.NullTime

	if err := scanner.Scan(
		&item.ID,
		&item.MessageType,
		&eventState,
		&projectID,
		&groupID,
		&item.PayloadJSON,
		&item.State,
		&item.AttemptCount,
		&item.NextAttemptAt,
		&expiresAt,
		&lockedAt,
		&lockedBy,
		&lastErrorCode,
		&lastErrorMessage,
		&doneAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if eventState.Valid {
		value := normalizeAlertDispatchEventState(AlertDispatchEventState(eventState.String))
		if value != "" {
			item.EventState = &value
		}
	}
	if projectID.Valid {
		value := projectID.UUID
		item.ProjectID = &value
	}
	if groupID.Valid {
		value := groupID.UUID
		item.GroupID = &value
	}
	item.ExpiresAt = nullTimePtr(expiresAt)
	item.LockedAt = nullTimePtr(lockedAt)
	if lockedBy.Valid {
		item.LockedBy = strings.TrimSpace(lockedBy.String)
	}
	if lastErrorCode.Valid {
		item.LastErrorCode = strings.TrimSpace(lastErrorCode.String)
	}
	if lastErrorMessage.Valid {
		item.LastErrorMessage = strings.TrimSpace(lastErrorMessage.String)
	}
	item.DoneAt = nullTimePtr(doneAt)
	return &item, nil
}

func (s *PostgresStore) EnqueueAlertDispatchJob(input AlertDispatchEnqueueInput) (*AlertDispatchJob, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	messageType := normalizeAlertDispatchMessageType(input.MessageType)
	if messageType == "" {
		return nil, ErrInvalidPayload
	}
	if input.PayloadJSON == nil {
		input.PayloadJSON = json.RawMessage(`{}`)
	}
	if !json.Valid(input.PayloadJSON) {
		return nil, ErrInvalidPayload
	}
	var eventState *string
	var projectID *uuid.UUID
	var groupID *uuid.UUID
	if messageType == AlertDispatchMessageTypeAlertEvent {
		if input.EventState == nil || normalizeAlertDispatchEventState(*input.EventState) == "" {
			return nil, ErrInvalidPayload
		}
		if input.ProjectID == nil || *input.ProjectID == uuid.Nil {
			return nil, ErrInvalidPayload
		}
		if input.GroupID == nil || *input.GroupID == uuid.Nil {
			return nil, ErrInvalidPayload
		}
		v := string(normalizeAlertDispatchEventState(*input.EventState))
		eventState = &v
		projectID = input.ProjectID
		groupID = input.GroupID
	}
	nextAttemptAt := time.Now().UTC()
	if input.NextAttemptAt != nil {
		nextAttemptAt = input.NextAttemptAt.UTC()
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO alert_dispatch_queue (
  message_type, event_state, project_id, group_id, payload_json,
  state, attempt_count, next_attempt_at, expires_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, 'PENDING', 0, $6, $7, NOW(), NOW())
RETURNING
  id, message_type, event_state, project_id, group_id, payload_json,
  state, attempt_count, next_attempt_at, expires_at, locked_at, locked_by,
  last_error_code, last_error_message, done_at, created_at, updated_at
`, string(messageType), eventState, projectID, groupID, input.PayloadJSON, nextAttemptAt, input.ExpiresAt)
	item, err := scanAlertDispatchJobRow(row)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) ClaimAlertDispatchJobs(messageType AlertDispatchMessageType, limit int, lockedBy string) ([]AlertDispatchJob, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	normalizedType := normalizeAlertDispatchMessageType(messageType)
	if normalizedType == "" || limit <= 0 {
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
  FROM alert_dispatch_queue
  WHERE message_type = $1
    AND state IN ('PENDING', 'RETRY')
    AND next_attempt_at <= NOW()
    AND (expires_at IS NULL OR expires_at > NOW())
  ORDER BY next_attempt_at ASC, created_at ASC
  FOR UPDATE SKIP LOCKED
  LIMIT $2
)
UPDATE alert_dispatch_queue q
SET state = 'IN_FLIGHT',
    attempt_count = q.attempt_count + 1,
    locked_at = NOW(),
    locked_by = $3,
    updated_at = NOW()
FROM next_jobs
WHERE q.id = next_jobs.id
RETURNING
  q.id, q.message_type, q.event_state, q.project_id, q.group_id, q.payload_json,
  q.state, q.attempt_count, q.next_attempt_at, q.expires_at, q.locked_at, q.locked_by,
  q.last_error_code, q.last_error_message, q.done_at, q.created_at, q.updated_at
`, string(normalizedType), limit, lockedBy)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AlertDispatchJob, 0, limit)
	for rows.Next() {
		item, scanErr := scanAlertDispatchJobRow(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) MarkAlertDispatchJobDone(id uuid.UUID) error {
	return s.updateAlertDispatchJobState(id, AlertDispatchQueueStateDone, nil, "", "")
}

func (s *PostgresStore) MarkAlertDispatchJobRetry(id uuid.UUID, nextAttemptAt time.Time, errorCode, errorMessage string) error {
	next := nextAttemptAt.UTC()
	return s.updateAlertDispatchJobState(id, AlertDispatchQueueStateRetry, &next, errorCode, errorMessage)
}

func (s *PostgresStore) MarkAlertDispatchJobDead(id uuid.UUID, errorCode, errorMessage string) error {
	return s.updateAlertDispatchJobState(id, AlertDispatchQueueStateDead, nil, errorCode, errorMessage)
}

func (s *PostgresStore) updateAlertDispatchJobState(id uuid.UUID, state AlertDispatchQueueState, nextAttemptAt *time.Time, errorCode, errorMessage string) error {
	if s == nil {
		return errors.New("store is nil")
	}
	if id == uuid.Nil {
		return ErrInvalidPayload
	}
	normalizedState := normalizeAlertDispatchQueueState(state)
	if normalizedState == "" || normalizedState == AlertDispatchQueueStateInFlight {
		return ErrInvalidPayload
	}
	errorCode = strings.TrimSpace(errorCode)
	if len(errorCode) > 128 {
		errorCode = errorCode[:128]
	}
	errorMessage = strings.TrimSpace(errorMessage)
	if len(errorMessage) > 2048 {
		errorMessage = errorMessage[:2048]
	}
	ctx, cancel := s.ctx()
	defer cancel()

	doneAt := sql.NullTime{}
	if normalizedState == AlertDispatchQueueStateDone || normalizedState == AlertDispatchQueueStateDead {
		doneAt = sql.NullTime{Valid: true, Time: time.Now().UTC()}
	}
	var nextAttempt any = nil
	if nextAttemptAt != nil {
		nextAttempt = nextAttemptAt.UTC()
	}

	result, err := s.db.ExecContext(ctx, `
UPDATE alert_dispatch_queue
SET state = $2,
    next_attempt_at = COALESCE($3, next_attempt_at),
    locked_at = NULL,
    locked_by = NULL,
    last_error_code = NULLIF($4, ''),
    last_error_message = NULLIF($5, ''),
    done_at = $6,
    updated_at = NOW()
WHERE id = $1
`, id, string(normalizedState), nextAttempt, errorCode, errorMessage, nullTime(doneAt))
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) RequeueStaleAlertDispatchJobs(staleAfter time.Duration, limit int) (int, error) {
	if s == nil {
		return 0, errors.New("store is nil")
	}
	if staleAfter <= 0 || limit < 0 {
		return 0, ErrInvalidPayload
	}
	seconds := int(staleAfter.Seconds())
	if seconds < 1 {
		seconds = 1
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
WITH candidates AS (
  SELECT id
  FROM alert_dispatch_queue
  WHERE state = 'IN_FLIGHT'
    AND locked_at <= NOW() - ($1 * interval '1 second')
  ORDER BY locked_at ASC
  LIMIT NULLIF($2, 0)
)
UPDATE alert_dispatch_queue q
SET state = 'RETRY',
    next_attempt_at = NOW(),
    locked_at = NULL,
    locked_by = NULL,
    updated_at = NOW()
FROM candidates c
WHERE q.id = c.id
RETURNING q.id
`, seconds, limit)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			return count, scanErr
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	return count, nil
}

func (s *PostgresStore) UpdateAlertGroupLastNotifiedAt(projectID, groupID uuid.UUID, notifiedAt time.Time) error {
	if s == nil {
		return errors.New("store is nil")
	}
	if projectID == uuid.Nil || groupID == uuid.Nil {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	result, err := s.db.ExecContext(ctx, `
UPDATE alert_groups
SET last_notified_at = $3,
    updated_at = NOW()
WHERE project_id = $1 AND id = $2
`, projectID, groupID, notifiedAt.UTC())
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ListEnabledAlertProjects(connectorType ConnectorType) ([]uuid.UUID, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if !ValidConnectorType(connectorType) {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
SELECT project_id
FROM (
    SELECT DISTINCT acs.project_id AS project_id
    FROM alert_connector_settings acs
    WHERE acs.connector_type = $1
      AND acs.is_enabled = TRUE

    UNION

    SELECT DISTINCT cc.scope_id AS project_id
    FROM connector_configs cc
    WHERE cc.connector_type = $1
      AND cc.scope_type = 'PROJECT'
      AND cc.scope_id IS NOT NULL
      AND cc.is_enabled = TRUE
      AND TRIM(COALESCE(cc.config_json::text, '')) <> '{}'
      AND TRIM(COALESCE(cc.config_json::text, '')) <> ''
      AND NOT EXISTS (
          SELECT 1
          FROM alert_connector_settings acs2
          WHERE acs2.project_id = cc.scope_id
            AND acs2.connector_type = cc.connector_type
      )
) enabled_projects
ORDER BY project_id ASC
`, string(connectorType))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]uuid.UUID, 0, 32)
	for rows.Next() {
		var id uuid.UUID
		if scanErr := rows.Scan(&id); scanErr != nil {
			return nil, scanErr
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) ListProjectAdminEmails(projectID uuid.UUID) ([]string, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT LOWER(TRIM(u.email)) AS email
FROM project_memberships pm
JOIN users u ON u.id = pm.user_id
WHERE pm.project_id = $1
  AND pm.project_role = 'ADMIN'
  AND TRIM(COALESCE(u.email, '')) <> ''
ORDER BY email ASC
`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]string, 0, 16)
	for rows.Next() {
		var email string
		if scanErr := rows.Scan(&email); scanErr != nil {
			return nil, scanErr
		}
		if email = strings.TrimSpace(email); email != "" {
			out = append(out, email)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) GetLatestAlertOccurrenceContext(projectID, groupID uuid.UUID) (*AlertOccurrenceContext, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || groupID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
SELECT product_id, scope_id, test_id
FROM alert_occurrences
WHERE project_id = $1 AND group_id = $2
ORDER BY occurred_at DESC
LIMIT 1
`, projectID, groupID)
	var productID uuid.NullUUID
	var scopeID uuid.NullUUID
	var testID uuid.NullUUID
	if err := row.Scan(&productID, &scopeID, &testID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	ctxOut := &AlertOccurrenceContext{}
	if productID.Valid {
		value := productID.UUID
		ctxOut.ProductID = &value
	}
	if scopeID.Valid {
		value := scopeID.UUID
		ctxOut.ScopeID = &value
	}
	if testID.Valid {
		value := testID.UUID
		ctxOut.TestID = &value
	}
	return ctxOut, nil
}

func (s *PostgresStore) ListAlertGroupComponentContexts(projectID, groupID uuid.UUID) ([]AlertGroupComponentContext, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || groupID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT
  o.product_id,
  o.scope_id,
  o.test_id,
  TRIM(COALESCE(o.entity_ref, '')) AS component_purl,
  TRIM(COALESCE(o.details->>'malwarePurl', '')) AS malware_purl
FROM alert_occurrences o
WHERE o.project_id = $1
  AND o.group_id = $2
  AND o.product_id IS NOT NULL
  AND o.scope_id IS NOT NULL
  AND o.test_id IS NOT NULL
  AND TRIM(COALESCE(o.entity_ref, '')) <> ''
ORDER BY o.test_id ASC, component_purl ASC
`, projectID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AlertGroupComponentContext, 0, 8)
	for rows.Next() {
		var item AlertGroupComponentContext
		if scanErr := rows.Scan(
			&item.ProductID,
			&item.ScopeID,
			&item.TestID,
			&item.ComponentPURL,
			&item.MalwarePURL,
		); scanErr != nil {
			return nil, scanErr
		}
		item.ComponentPURL = strings.TrimSpace(item.ComponentPURL)
		item.MalwarePURL = strings.TrimSpace(item.MalwarePURL)
		if item.ComponentPURL == "" {
			continue
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) enqueueAlertEventTx(tx *sql.Tx, projectID, groupID uuid.UUID, eventState AlertDispatchEventState, payload json.RawMessage, expiresAt *time.Time) error {
	if tx == nil {
		return errors.New("tx is nil")
	}
	if projectID == uuid.Nil || groupID == uuid.Nil {
		return ErrInvalidPayload
	}
	state := normalizeAlertDispatchEventState(eventState)
	if state == "" {
		return ErrInvalidPayload
	}
	if payload == nil {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return ErrInvalidPayload
	}
	var expires any = nil
	if expiresAt != nil {
		expires = expiresAt.UTC()
	}
	_, err := tx.Exec(`
INSERT INTO alert_dispatch_queue (
  message_type, event_state, project_id, group_id, payload_json,
  state, attempt_count, next_attempt_at, expires_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, 'PENDING', 0, NOW(), $6, NOW(), NOW())
`, string(AlertDispatchMessageTypeAlertEvent), string(state), projectID, groupID, payload, expires)
	return err
}
