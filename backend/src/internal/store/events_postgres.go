package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
)

const (
	eventAckAction = "EVENT_ACK"
)

func (s *PostgresStore) CountOpenEvents(q EventsQuery) (int, error) {
	q.NormalizeDefaults()
	if err := validateEventsQuery(q); err != nil {
		return 0, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	where, args, err := buildEventsBaseWhere(q, true /* includeTimeRange */)
	if err != nil {
		return 0, err
	}

	// Count distinct event_keys that are still open.
	query := fmt.Sprintf(`
WITH base AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS last_seen_at
  FROM audit_logs
  WHERE action <> '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
    %s
  GROUP BY details->>'event_key'
),
acks AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS acknowledged_at
  FROM audit_logs
  WHERE action = '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
  GROUP BY details->>'event_key'
)
SELECT count(*)::int
FROM base
LEFT JOIN acks USING(event_key)
WHERE acks.acknowledged_at IS NULL OR base.last_seen_at > acks.acknowledged_at
`, eventAckAction, where, eventAckAction)

	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *PostgresStore) ListEvents(q EventsQuery) ([]EventAggregate, int, error) {
	q.NormalizeDefaults()
	if err := validateEventsQuery(q); err != nil {
		return nil, 0, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	where, args, err := buildEventsBaseWhere(q, true /* includeTimeRange */)
	if err != nil {
		return nil, 0, err
	}

	statusWhereAgg := ""
	statusWhereBase := ""
	if q.Status == EventsStatusOpen {
		statusWhereAgg = "WHERE acks.acknowledged_at IS NULL OR agg.last_seen_at > acks.acknowledged_at"
		statusWhereBase = "WHERE acks.acknowledged_at IS NULL OR base.last_seen_at > acks.acknowledged_at"
	} else if q.Status == EventsStatusAcknowledged {
		statusWhereAgg = "WHERE acks.acknowledged_at IS NOT NULL AND agg.last_seen_at <= acks.acknowledged_at"
		statusWhereBase = "WHERE acks.acknowledged_at IS NOT NULL AND base.last_seen_at <= acks.acknowledged_at"
	}

	listQuery := fmt.Sprintf(`
WITH base AS (
  SELECT
    details->>'event_key' AS event_key,
    details->>'category' AS category,
    details->>'severity' AS severity,
    details->>'min_role' AS min_role,
    details->>'title' AS title,
    details->>'message' AS message,
    details->>'component' AS component,
    details->>'errorId' AS error_id,
    details->>'projectId' AS project_id,
    created_at
  FROM audit_logs
  WHERE action <> '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
    %s
),
agg AS (
  SELECT
    event_key,
    (array_agg(category ORDER BY created_at DESC))[1] AS category,
    (array_agg(severity ORDER BY created_at DESC))[1] AS severity,
    (array_agg(min_role ORDER BY created_at DESC))[1] AS min_role,
    (array_agg(title ORDER BY created_at DESC))[1] AS title,
    (array_agg(message ORDER BY created_at DESC))[1] AS message,
    (array_agg(component ORDER BY created_at DESC))[1] AS component,
    (array_agg(error_id ORDER BY created_at DESC))[1] AS error_id,
    (array_agg(project_id ORDER BY created_at DESC))[1] AS project_id,
    min(created_at) AS first_seen_at,
    max(created_at) AS last_seen_at,
    count(*)::int AS occurrences
  FROM base
  GROUP BY event_key
),
acks AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS acknowledged_at
  FROM audit_logs
  WHERE action = '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
  GROUP BY details->>'event_key'
)
SELECT
  agg.event_key,
  COALESCE(agg.category,'') AS category,
  COALESCE(agg.severity,'') AS severity,
  COALESCE(agg.min_role,'') AS min_role,
  COALESCE(agg.title,'') AS title,
  COALESCE(agg.message,'') AS message,
  COALESCE(agg.component,'') AS component,
  COALESCE(agg.error_id,'') AS error_id,
  COALESCE(agg.project_id,'') AS project_id,
  agg.first_seen_at,
  agg.last_seen_at,
  agg.occurrences,
  acks.acknowledged_at,
  CASE
    WHEN acks.acknowledged_at IS NULL OR agg.last_seen_at > acks.acknowledged_at THEN 'open'
    ELSE 'acknowledged'
  END AS status
FROM agg
LEFT JOIN acks USING(event_key)
%s
ORDER BY agg.last_seen_at DESC
LIMIT $%d OFFSET $%d
`, eventAckAction, where, eventAckAction, statusWhereAgg, len(args)+1, len(args)+2)

	listArgs := append(args, q.Limit, q.Offset)
	rows, err := s.db.QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]EventAggregate, 0)
	for rows.Next() {
		var item EventAggregate
		if err := rows.Scan(
			&item.EventKey,
			&item.Category,
			&item.Severity,
			&item.MinRole,
			&item.Title,
			&item.Message,
			&item.Component,
			&item.ErrorID,
			&item.ProjectID,
			&item.FirstSeenAt,
			&item.LastSeenAt,
			&item.Occurrences,
			&item.AcknowledgedAt,
			&item.Status,
		); err != nil {
			return nil, 0, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	countQuery := fmt.Sprintf(`
WITH base AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS last_seen_at
  FROM audit_logs
  WHERE action <> '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
    %s
  GROUP BY details->>'event_key'
),
acks AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS acknowledged_at
  FROM audit_logs
  WHERE action = '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
  GROUP BY details->>'event_key'
)
SELECT count(*)::int
FROM base
LEFT JOIN acks USING(event_key)
%s
`, eventAckAction, where, eventAckAction, statusWhereBase)

	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *PostgresStore) GetEvent(eventKey string, q EventsQuery, occurrencesLimit int) (*EventAggregate, []models.AuditLog, error) {
	eventKey = strings.TrimSpace(eventKey)
	if eventKey == "" {
		return nil, nil, ErrInvalidPayload
	}
	if occurrencesLimit <= 0 || occurrencesLimit > 200 {
		occurrencesLimit = 50
	}
	q.NormalizeDefaults()
	// For details, we always force query to include the specific event key, so other filters are optional.
	q.Query = ""
	if err := validateEventsQuery(q); err != nil {
		return nil, nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	where, args, err := buildEventsBaseWhere(q, false /* includeTimeRange */)
	if err != nil {
		return nil, nil, err
	}
	args = append(args, eventKey)
	eventKeyArg := len(args)

	aggQuery := fmt.Sprintf(`
WITH base AS (
  SELECT
    details->>'event_key' AS event_key,
    details->>'category' AS category,
    details->>'severity' AS severity,
    details->>'min_role' AS min_role,
    details->>'title' AS title,
    details->>'message' AS message,
    details->>'component' AS component,
    details->>'errorId' AS error_id,
    details->>'projectId' AS project_id,
    created_at
  FROM audit_logs
  WHERE action <> '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
    %s
    AND details->>'event_key' = $%d
),
agg AS (
  SELECT
    event_key,
    (array_agg(category ORDER BY created_at DESC))[1] AS category,
    (array_agg(severity ORDER BY created_at DESC))[1] AS severity,
    (array_agg(min_role ORDER BY created_at DESC))[1] AS min_role,
    (array_agg(title ORDER BY created_at DESC))[1] AS title,
    (array_agg(message ORDER BY created_at DESC))[1] AS message,
    (array_agg(component ORDER BY created_at DESC))[1] AS component,
    (array_agg(error_id ORDER BY created_at DESC))[1] AS error_id,
    (array_agg(project_id ORDER BY created_at DESC))[1] AS project_id,
    min(created_at) AS first_seen_at,
    max(created_at) AS last_seen_at,
    count(*)::int AS occurrences
  FROM base
  GROUP BY event_key
),
acks AS (
  SELECT details->>'event_key' AS event_key, max(created_at) AS acknowledged_at
  FROM audit_logs
  WHERE action = '%s'
    AND details ? 'event_key'
    AND COALESCE(details->>'event_key','') <> ''
  GROUP BY details->>'event_key'
)
SELECT
  agg.event_key,
  COALESCE(agg.category,'') AS category,
  COALESCE(agg.severity,'') AS severity,
  COALESCE(agg.min_role,'') AS min_role,
  COALESCE(agg.title,'') AS title,
  COALESCE(agg.message,'') AS message,
  COALESCE(agg.component,'') AS component,
  COALESCE(agg.error_id,'') AS error_id,
  COALESCE(agg.project_id,'') AS project_id,
  agg.first_seen_at,
  agg.last_seen_at,
  agg.occurrences,
  acks.acknowledged_at,
  CASE
    WHEN acks.acknowledged_at IS NULL OR agg.last_seen_at > acks.acknowledged_at THEN 'open'
    ELSE 'acknowledged'
  END AS status
FROM agg
LEFT JOIN acks USING(event_key)
`, eventAckAction, where, eventKeyArg, eventAckAction)

	var item EventAggregate
	if err := s.db.QueryRowContext(ctx, aggQuery, args...).Scan(
		&item.EventKey,
		&item.Category,
		&item.Severity,
		&item.MinRole,
		&item.Title,
		&item.Message,
		&item.Component,
		&item.ErrorID,
		&item.ProjectID,
		&item.FirstSeenAt,
		&item.LastSeenAt,
		&item.Occurrences,
		&item.AcknowledgedAt,
		&item.Status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	occQuery := fmt.Sprintf(`
SELECT id, actor_id, action, entity_type, entity_id, details, ip_address, created_at
FROM audit_logs
WHERE action <> '%s'
  AND details ? 'event_key'
  AND COALESCE(details->>'event_key','') <> ''
  %s
  AND details->>'event_key' = $%d
ORDER BY created_at DESC
LIMIT $%d
`, eventAckAction, where, eventKeyArg, eventKeyArg+1)
	occArgs := append(args, occurrencesLimit)
	rows, err := s.db.QueryContext(ctx, occQuery, occArgs...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	occurrences := make([]models.AuditLog, 0)
	for rows.Next() {
		entry, err := scanAuditLogRow(rows)
		if err != nil {
			return nil, nil, err
		}
		occurrences = append(occurrences, *entry)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return &item, occurrences, nil
}

func validateEventsQuery(q EventsQuery) error {
	if q.Limit <= 0 || q.Limit > 200 {
		return ErrInvalidPayload
	}
	if q.Offset < 0 {
		return ErrInvalidPayload
	}
	switch q.Status {
	case "", EventsStatusOpen, EventsStatusAcknowledged:
	default:
		return ErrInvalidPayload
	}
	switch q.ViewerRole {
	case EventsViewerRoleAdmin, EventsViewerRoleWrite, EventsViewerRoleRead:
	default:
		return ErrInvalidPayload
	}
	if q.ViewerRole == EventsViewerRoleRead && strings.TrimSpace(q.ViewerID) == "" {
		return ErrInvalidPayload
	}
	for _, sev := range q.Severities {
		if !eventmeta.ValidSeverity(string(sev)) {
			return ErrInvalidPayload
		}
	}
	for _, cat := range q.CategoriesError {
		if !eventmeta.ValidCategory(string(cat)) {
			return ErrInvalidPayload
		}
	}
	for _, cat := range q.CategoriesWarn {
		if !eventmeta.ValidCategory(string(cat)) {
			return ErrInvalidPayload
		}
	}
	for _, cat := range q.CategoriesInfo {
		if !eventmeta.ValidCategory(string(cat)) {
			return ErrInvalidPayload
		}
	}
	if len(q.Severities) == 0 {
		return ErrInvalidPayload
	}
	if q.From.IsZero() || q.To.IsZero() || q.From.After(q.To) {
		return ErrInvalidPayload
	}
	if q.Query != "" && len(q.Query) < 2 {
		return ErrInvalidPayload
	}
	if len(q.Query) > 128 {
		return ErrInvalidPayload
	}
	if strings.TrimSpace(q.ProjectID) != "" {
		if _, err := uuid.Parse(strings.TrimSpace(q.ProjectID)); err != nil {
			return ErrInvalidPayload
		}
	}
	return nil
}

func buildEventsBaseWhere(q EventsQuery, includeTimeRange bool) (string, []any, error) {
	parts := make([]string, 0, 8)
	args := make([]any, 0, 8)

	addIn := func(expr string, values []string) {
		if len(values) == 0 {
			return
		}
		placeholders := make([]string, 0, len(values))
		for _, v := range values {
			args = append(args, v)
			placeholders = append(placeholders, fmt.Sprintf("$%d", len(args)))
		}
		parts = append(parts, fmt.Sprintf("AND %s IN (%s)", expr, strings.Join(placeholders, ", ")))
	}

	if includeTimeRange {
		args = append(args, q.From, q.To)
		parts = append(parts, fmt.Sprintf("AND created_at >= $%d AND created_at <= $%d", len(args)-1, len(args)))
	}

	if projectID := strings.TrimSpace(q.ProjectID); projectID != "" {
		args = append(args, projectID)
		parts = append(parts, fmt.Sprintf("AND (COALESCE(details->>'projectId','') = '' OR details->>'projectId' = $%d)", len(args)))
	}

	// severity/category alignment:
	// Build an OR expression so each severity can optionally apply its own category allowlist.
	sevClauses := make([]string, 0, len(q.Severities))
	for _, sev := range q.Severities {
		sevValue := string(sev)
		args = append(args, sevValue)
		sevArg := fmt.Sprintf("$%d", len(args))

		var cats []eventmeta.Category
		switch sev {
		case eventmeta.SeverityError:
			cats = q.CategoriesError
		case eventmeta.SeverityWarn:
			cats = q.CategoriesWarn
		case eventmeta.SeverityInfo:
			cats = q.CategoriesInfo
		default:
			cats = nil
		}

		if len(cats) == 0 {
			sevClauses = append(sevClauses, fmt.Sprintf("details->>'severity' = %s", sevArg))
			continue
		}
		catPlaceholders := make([]string, 0, len(cats))
		for _, c := range cats {
			args = append(args, string(c))
			catPlaceholders = append(catPlaceholders, fmt.Sprintf("$%d", len(args)))
		}
		sevClauses = append(sevClauses, fmt.Sprintf("(details->>'severity' = %s AND details->>'category' IN (%s))", sevArg, strings.Join(catPlaceholders, ", ")))
	}
	if len(sevClauses) > 0 {
		parts = append(parts, fmt.Sprintf("AND (%s)", strings.Join(sevClauses, " OR ")))
	}

	// RBAC: min_role check.
	switch q.ViewerRole {
	case EventsViewerRoleAdmin:
		// no filter
	case EventsViewerRoleWrite:
		addIn("details->>'min_role'", []string{string(eventmeta.MinRoleRead), string(eventmeta.MinRoleWrite)})
	case EventsViewerRoleRead:
		args = append(args, string(eventmeta.MinRoleRead))
		parts = append(parts, fmt.Sprintf("AND details->>'min_role' = $%d", len(args)))
		args = append(args, strings.TrimSpace(q.ViewerID))
		// self-only: actor_id = current user OR entity_type='user' AND entity_id=current user
		parts = append(parts, fmt.Sprintf("AND (actor_id::text = $%d OR (LOWER(entity_type) = 'user' AND entity_id::text = $%d))", len(args), len(args)))
	default:
		return "", nil, ErrInvalidPayload
	}

	// q filter (optional): title/message/event_key ILIKE %q%
	if q.Query != "" {
		args = append(args, "%"+strings.ToLower(q.Query)+"%")
		parts = append(parts, fmt.Sprintf("AND (LOWER(COALESCE(details->>'event_key','')) LIKE $%d OR LOWER(COALESCE(details->>'title','')) LIKE $%d OR LOWER(COALESCE(details->>'message','')) LIKE $%d)", len(args), len(args), len(args)))
	}

	return "\n    " + strings.Join(parts, "\n    "), args, nil
}
