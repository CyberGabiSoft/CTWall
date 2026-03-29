package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

func (s *PostgresStore) ListAlertDedupRules(projectID uuid.UUID, alertType string) ([]models.AlertDedupRule, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	alertType = strings.TrimSpace(alertType)
	if alertType == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx, `
SELECT
  id, project_id, alert_type, dedup_scope, product_id, scope_id, test_id, min_severity, enabled, created_at, updated_at
FROM alert_dedup_rules
WHERE project_id = $1 AND alert_type = $2
ORDER BY
  CASE dedup_scope
    WHEN 'GLOBAL' THEN 4
    WHEN 'PRODUCT' THEN 3
    WHEN 'SCOPE' THEN 2
    WHEN 'TEST' THEN 1
    ELSE 9
  END ASC,
  updated_at DESC
`, projectID, alertType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]models.AlertDedupRule, 0, 8)
	for rows.Next() {
		var it models.AlertDedupRule
		if err := rows.Scan(
			&it.ID,
			&it.ProjectID,
			&it.AlertType,
			&it.DedupScope,
			&it.ProductID,
			&it.ScopeID,
			&it.TestID,
			&it.MinSeverity,
			&it.Enabled,
			&it.CreatedAt,
			&it.UpdatedAt,
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

func (s *PostgresStore) ReplaceAlertDedupRules(projectID uuid.UUID, alertType string, rules []AlertDedupRuleInput) ([]models.AlertDedupRule, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	alertType = strings.TrimSpace(alertType)
	if alertType == "" {
		return nil, ErrInvalidPayload
	}

	normalized := make([]AlertDedupRuleInput, 0, len(rules)+1)
	hasGlobal := false
	for _, rule := range rules {
		scope := normalizeAlertDedupScope(string(rule.DedupScope))
		if scope == "" {
			return nil, ErrInvalidPayload
		}
		ruleType := strings.TrimSpace(rule.AlertType)
		if ruleType == "" {
			ruleType = alertType
		}
		if !strings.EqualFold(ruleType, alertType) {
			return nil, ErrInvalidPayload
		}
		rule.AlertType = alertType
		rule.DedupScope = scope
		switch scope {
		case AlertDedupScopeGlobal:
			rule.ProductID = nil
			rule.ScopeID = nil
			rule.TestID = nil
			hasGlobal = true
		case AlertDedupScopeProduct:
			if rule.ProductID == nil || *rule.ProductID == uuid.Nil || rule.ScopeID != nil || rule.TestID != nil {
				return nil, ErrInvalidPayload
			}
		case AlertDedupScopeScope:
			if rule.ScopeID == nil || *rule.ScopeID == uuid.Nil || rule.ProductID != nil || rule.TestID != nil {
				return nil, ErrInvalidPayload
			}
		case AlertDedupScopeTest:
			if rule.TestID == nil || *rule.TestID == uuid.Nil || rule.ProductID != nil || rule.ScopeID != nil {
				return nil, ErrInvalidPayload
			}
		default:
			return nil, ErrInvalidPayload
		}
		normalized = append(normalized, rule)
	}
	shouldAutoAppendGlobal := !hasGlobal && !strings.EqualFold(alertType, "malware.detected")
	if shouldAutoAppendGlobal {
		normalized = append(normalized, AlertDedupRuleInput{
			AlertType:   alertType,
			DedupScope:  AlertDedupScopeGlobal,
			MinSeverity: AlertMinSeverityInfo,
			Enabled:     true,
		})
	}

	// Dedupe by identity.
	dedup := make(map[string]AlertDedupRuleInput, len(normalized))
	for _, rule := range normalized {
		identity := alertDedupRuleIdentity(projectID, alertType, rule)
		dedup[identity] = rule
	}
	normalized = normalized[:0]
	for _, item := range dedup {
		if item.MinSeverity == "" {
			item.MinSeverity = AlertMinSeverityInfo
		}
		item.MinSeverity = normalizeAlertMinSeverity(string(item.MinSeverity))
		if item.MinSeverity == "" {
			return nil, ErrInvalidPayload
		}
		normalized = append(normalized, item)
	}

	// Validate targets belong to the active project.
	productIDs := make([]uuid.UUID, 0, len(normalized))
	scopeIDs := make([]uuid.UUID, 0, len(normalized))
	testIDs := make([]uuid.UUID, 0, len(normalized))
	for _, rule := range normalized {
		switch rule.DedupScope {
		case AlertDedupScopeProduct:
			productIDs = append(productIDs, *rule.ProductID)
		case AlertDedupScopeScope:
			scopeIDs = append(scopeIDs, *rule.ScopeID)
		case AlertDedupScopeTest:
			testIDs = append(testIDs, *rule.TestID)
		}
	}
	if err := s.ValidateAlertRouteTargets(projectID, AlertRouteTargetProduct, productIDs); err != nil {
		return nil, err
	}
	if err := s.ValidateAlertRouteTargets(projectID, AlertRouteTargetScope, scopeIDs); err != nil {
		return nil, err
	}
	if err := s.ValidateAlertRouteTargets(projectID, AlertRouteTargetTest, testIDs); err != nil {
		return nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
DELETE FROM alert_dedup_rules
WHERE project_id = $1 AND alert_type = $2
`, projectID, alertType); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	for _, rule := range normalized {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_dedup_rules (
  project_id, alert_type, dedup_scope, product_id, scope_id, test_id, min_severity, enabled, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
`, projectID, alertType, string(rule.DedupScope), rule.ProductID, rule.ScopeID, rule.TestID, string(rule.MinSeverity), rule.Enabled, now); err != nil {
			if isForeignKeyViolation(err) {
				return nil, ErrInvalidPayload
			}
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.ListAlertDedupRules(projectID, alertType)
}

func alertDedupRuleIdentity(projectID uuid.UUID, alertType string, rule AlertDedupRuleInput) string {
	productID := uuid.Nil
	scopeID := uuid.Nil
	testID := uuid.Nil
	if rule.ProductID != nil {
		productID = *rule.ProductID
	}
	if rule.ScopeID != nil {
		scopeID = *rule.ScopeID
	}
	if rule.TestID != nil {
		testID = *rule.TestID
	}
	return fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s",
		projectID.String(),
		alertType,
		string(rule.DedupScope),
		productID.String(),
		scopeID.String(),
		testID.String(),
	)
}

func (s *PostgresStore) ResolveAlertDedupRule(input AlertDedupRuleResolutionInput) (*models.AlertDedupRule, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if input.ProjectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	alertType := strings.TrimSpace(input.AlertType)
	if alertType == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	// Query all enabled candidates in one pass and pick highest precedence.
	rows, err := s.db.QueryContext(ctx, `
SELECT
  id, project_id, alert_type, dedup_scope, product_id, scope_id, test_id, min_severity, enabled, created_at, updated_at
FROM alert_dedup_rules
WHERE project_id = $1
  AND alert_type = $2
  AND enabled = TRUE
ORDER BY
  CASE dedup_scope
    WHEN 'TEST' THEN 1
    WHEN 'SCOPE' THEN 2
    WHEN 'PRODUCT' THEN 3
    WHEN 'GLOBAL' THEN 4
    ELSE 9
  END ASC,
  updated_at DESC
`, input.ProjectID, alertType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var globalRule *models.AlertDedupRule
	for rows.Next() {
		var it models.AlertDedupRule
		if err := rows.Scan(
			&it.ID,
			&it.ProjectID,
			&it.AlertType,
			&it.DedupScope,
			&it.ProductID,
			&it.ScopeID,
			&it.TestID,
			&it.MinSeverity,
			&it.Enabled,
			&it.CreatedAt,
			&it.UpdatedAt,
		); err != nil {
			return nil, err
		}

		switch normalizeAlertDedupScope(it.DedupScope) {
		case AlertDedupScopeTest:
			if input.TestID != nil && it.TestID != nil && *input.TestID == *it.TestID {
				return &it, nil
			}
		case AlertDedupScopeScope:
			if input.ScopeID != nil && it.ScopeID != nil && *input.ScopeID == *it.ScopeID {
				return &it, nil
			}
		case AlertDedupScopeProduct:
			if input.ProductID != nil && it.ProductID != nil && *input.ProductID == *it.ProductID {
				return &it, nil
			}
		case AlertDedupScopeGlobal:
			if globalRule == nil {
				rule := it
				globalRule = &rule
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Malware alerting is test-centric by default:
	// a new test with malware should create its own alert group, while reimports
	// in the same test should be deduplicated into the same group key.
	// We therefore prefer implicit TEST fallback over GLOBAL for malware.detected.
	if strings.EqualFold(alertType, "malware.detected") && input.TestID != nil {
		return &models.AlertDedupRule{
			ID:          uuid.Nil,
			ProjectID:   input.ProjectID,
			AlertType:   alertType,
			DedupScope:  string(AlertDedupScopeTest),
			MinSeverity: string(AlertMinSeverityInfo),
			Enabled:     true,
			TestID:      input.TestID,
		}, nil
	}

	if globalRule != nil {
		return globalRule, nil
	}

	// Implicit fallback keeps backward compatibility.
	return &models.AlertDedupRule{
		ID:          uuid.Nil,
		ProjectID:   input.ProjectID,
		AlertType:   alertType,
		DedupScope:  string(AlertDedupScopeGlobal),
		MinSeverity: string(AlertMinSeverityInfo),
		Enabled:     true,
	}, nil
}

func (s *PostgresStore) GetAlertDedupRuleByID(projectID, ruleID uuid.UUID) (*models.AlertDedupRule, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || ruleID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
SELECT
  id, project_id, alert_type, dedup_scope, product_id, scope_id, test_id, min_severity, enabled, created_at, updated_at
FROM alert_dedup_rules
WHERE project_id = $1 AND id = $2
LIMIT 1
`, projectID, ruleID)

	var item models.AlertDedupRule
	if err := row.Scan(
		&item.ID,
		&item.ProjectID,
		&item.AlertType,
		&item.DedupScope,
		&item.ProductID,
		&item.ScopeID,
		&item.TestID,
		&item.MinSeverity,
		&item.Enabled,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &item, nil
}

func buildMalwareDetectedGroupKey(projectID uuid.UUID, malwarePURL string, rule *models.AlertDedupRule, productID, scopeID, testID *uuid.UUID) string {
	scope := normalizeAlertDedupScope(rule.DedupScope)
	switch scope {
	case AlertDedupScopeTest:
		if testID != nil {
			return fmt.Sprintf(
				"project:%s|type:malware.detected|dedup_on:test|test_id:%s|malware_purl:%s",
				projectID.String(),
				testID.String(),
				malwarePURL,
			)
		}
	case AlertDedupScopeScope:
		if scopeID != nil {
			return fmt.Sprintf(
				"project:%s|type:malware.detected|dedup_on:scope|scope_id:%s|malware_purl:%s",
				projectID.String(),
				scopeID.String(),
				malwarePURL,
			)
		}
	case AlertDedupScopeProduct:
		if productID != nil {
			return fmt.Sprintf(
				"project:%s|type:malware.detected|dedup_on:product|product_id:%s|malware_purl:%s",
				projectID.String(),
				productID.String(),
				malwarePURL,
			)
		}
	}
	return fmt.Sprintf(
		"project:%s|type:malware.detected|malware_purl:%s",
		projectID.String(),
		malwarePURL,
	)
}

// ReconcileMalwareAlertGroup closes or re-opens a malware.detected group based on current effective OPEN findings.
// It does not store query results; it computes current state on demand.
