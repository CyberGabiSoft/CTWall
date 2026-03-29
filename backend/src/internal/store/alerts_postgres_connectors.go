package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

func (s *PostgresStore) GetAlertConnectorSettings(projectID uuid.UUID) ([]AlertConnectorSettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
SELECT project_id, connector_type, is_enabled, jira_dedup_rule_id, updated_at
FROM alert_connector_settings
WHERE project_id = $1
ORDER BY connector_type ASC
`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make([]AlertConnectorSettings, 0, 4)
	for rows.Next() {
		var item AlertConnectorSettings
		var connectorType string
		if err := rows.Scan(&item.ProjectID, &connectorType, &item.IsEnabled, &item.JiraDedupRuleID, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.ConnectorType = ConnectorType(connectorType)
		settings = append(settings, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Routes.
	routeRows, err := s.db.QueryContext(ctx, `
SELECT project_id, connector_type, target_type, target_id
FROM alert_routes
WHERE project_id = $1
ORDER BY connector_type ASC, target_type ASC, target_id ASC
`, projectID)
	if err != nil {
		return nil, err
	}
	defer routeRows.Close()

	type key struct {
		project uuid.UUID
		ct      string
	}
	byKey := make(map[key]int, len(settings))
	for idx := range settings {
		byKey[key{project: settings[idx].ProjectID, ct: string(settings[idx].ConnectorType)}] = idx
	}

	for routeRows.Next() {
		var pid uuid.UUID
		var ct string
		var tt string
		var tid uuid.UUID
		if err := routeRows.Scan(&pid, &ct, &tt, &tid); err != nil {
			return nil, err
		}
		idx, ok := byKey[key{project: pid, ct: ct}]
		if !ok {
			continue
		}
		settings[idx].Routes = append(settings[idx].Routes, AlertRouteRef{
			TargetType: AlertRouteTargetType(tt),
			TargetID:   tid,
		})
	}
	if err := routeRows.Err(); err != nil {
		return nil, err
	}

	return settings, nil
}

func (s *PostgresStore) UpsertAlertConnectorSettings(projectID uuid.UUID, connectorType ConnectorType, enabled bool, routes []AlertRouteRef) (*AlertConnectorSettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if !ValidConnectorType(connectorType) {
		return nil, ErrInvalidPayload
	}

	// Normalize and dedupe routes (no FK in DB; handler must validate target IDs belong to project).
	dedup := make(map[string]AlertRouteRef, len(routes))
	for _, r := range routes {
		if r.TargetID == uuid.Nil {
			continue
		}
		switch r.TargetType {
		case AlertRouteTargetProduct, AlertRouteTargetScope, AlertRouteTargetTest:
		default:
			continue
		}
		key := string(r.TargetType) + ":" + r.TargetID.String()
		dedup[key] = r
	}
	normalized := make([]AlertRouteRef, 0, len(dedup))
	for _, v := range dedup {
		normalized = append(normalized, v)
	}

	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_connector_settings (project_id, connector_type, is_enabled, jira_dedup_rule_id, created_at, updated_at)
VALUES ($1, $2, $3, NULL, $4, $4)
ON CONFLICT (project_id, connector_type) DO UPDATE
SET is_enabled = EXCLUDED.is_enabled,
    updated_at = EXCLUDED.updated_at
`, projectID, string(connectorType), enabled, now); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `
DELETE FROM alert_routes WHERE project_id = $1 AND connector_type = $2
`, projectID, string(connectorType)); err != nil {
		return nil, err
	}
	for _, r := range normalized {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_routes (project_id, connector_type, target_type, target_id, created_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING
`, projectID, string(connectorType), string(r.TargetType), r.TargetID, now); err != nil {
			return nil, err
		}
	}

	var out AlertConnectorSettings
	var ct string
	if err := tx.QueryRowContext(ctx, `
SELECT project_id, connector_type, is_enabled, jira_dedup_rule_id, updated_at
FROM alert_connector_settings
WHERE project_id = $1 AND connector_type = $2
`, projectID, string(connectorType)).Scan(&out.ProjectID, &ct, &out.IsEnabled, &out.JiraDedupRuleID, &out.UpdatedAt); err != nil {
		return nil, err
	}
	out.ConnectorType = ConnectorType(ct)
	out.Routes = normalized

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (s *PostgresStore) SetAlertConnectorJiraDedupRule(projectID uuid.UUID, dedupRuleID *uuid.UUID) (*AlertConnectorSettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if dedupRuleID != nil && *dedupRuleID == uuid.Nil {
		dedupRuleID = nil
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if dedupRuleID != nil {
		var rule models.AlertDedupRule
		if err := tx.QueryRowContext(ctx, `
SELECT id, project_id, alert_type, dedup_scope, product_id, scope_id, test_id, min_severity, enabled, created_at, updated_at
FROM alert_dedup_rules
WHERE project_id = $1 AND id = $2
LIMIT 1
FOR UPDATE
`, projectID, *dedupRuleID).Scan(
			&rule.ID,
			&rule.ProjectID,
			&rule.AlertType,
			&rule.DedupScope,
			&rule.ProductID,
			&rule.ScopeID,
			&rule.TestID,
			&rule.MinSeverity,
			&rule.Enabled,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrInvalidPayload
			}
			return nil, err
		}
		if !rule.Enabled || !strings.EqualFold(strings.TrimSpace(rule.AlertType), "malware.detected") {
			return nil, ErrInvalidPayload
		}
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_connector_settings (project_id, connector_type, is_enabled, jira_dedup_rule_id, created_at, updated_at)
VALUES ($1, 'JIRA', FALSE, $2, $3, $3)
ON CONFLICT (project_id, connector_type) DO UPDATE
SET jira_dedup_rule_id = EXCLUDED.jira_dedup_rule_id,
    updated_at = EXCLUDED.updated_at
`, projectID, dedupRuleID, now); err != nil {
		return nil, err
	}

	var out AlertConnectorSettings
	var ct string
	if err := tx.QueryRowContext(ctx, `
SELECT project_id, connector_type, is_enabled, jira_dedup_rule_id, updated_at
FROM alert_connector_settings
WHERE project_id = $1 AND connector_type = 'JIRA'
LIMIT 1
`, projectID).Scan(&out.ProjectID, &ct, &out.IsEnabled, &out.JiraDedupRuleID, &out.UpdatedAt); err != nil {
		return nil, err
	}
	out.ConnectorType = ConnectorType(ct)
	out.Routes = []AlertRouteRef{}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

// ValidateAlertRouteTargets ensures selected target IDs belong to the given project.
// It prevents routing rules from referencing objects from another project.
func (s *PostgresStore) ValidateAlertRouteTargets(projectID uuid.UUID, targetType AlertRouteTargetType, ids []uuid.UUID) error {
	if s == nil {
		return errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return ErrInvalidPayload
	}
	if len(ids) == 0 {
		return nil
	}
	uniq := make([]uuid.UUID, 0, len(ids))
	seen := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	if len(uniq) == 0 {
		return nil
	}

	ctx, cancel := s.ctx()
	defer cancel()

	var sqlText string
	switch targetType {
	case AlertRouteTargetProduct:
		sqlText = `SELECT COUNT(*) FROM products WHERE project_id = $1 AND id = ANY($2)`
	case AlertRouteTargetScope:
		sqlText = `
SELECT COUNT(*)
FROM scopes s
JOIN products p ON p.id = s.product_id
WHERE p.project_id = $1 AND s.id = ANY($2)
`
	case AlertRouteTargetTest:
		sqlText = `
SELECT COUNT(*)
FROM tests t
JOIN scopes s ON s.id = t.scope_id
JOIN products p ON p.id = s.product_id
WHERE p.project_id = $1 AND t.id = ANY($2)
`
	default:
		return ErrInvalidPayload
	}

	var count int
	if err := s.db.QueryRowContext(ctx, sqlText, projectID, uniq).Scan(&count); err != nil {
		return err
	}
	if count != len(uniq) {
		return ErrInvalidPayload
	}
	return nil
}
