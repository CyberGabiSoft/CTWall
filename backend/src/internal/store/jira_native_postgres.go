package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

func sanitizeJiraStringList(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func sanitizeSeverityPriorityMapping(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(input))
	for key, value := range input {
		k := strings.ToUpper(strings.TrimSpace(key))
		v := strings.TrimSpace(value)
		if k == "" || v == "" {
			continue
		}
		out[k] = v
	}
	return out
}

func sanitizeJiraIssueFieldsValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		item := strings.TrimSpace(typed)
		if item == "" {
			return nil, false
		}
		return item, true
	case bool:
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		return typed, true
	case int:
		return typed, true
	case int32:
		return typed, true
	case int64:
		return typed, true
	case json.Number:
		if asInt, err := typed.Int64(); err == nil {
			return asInt, true
		}
		if asFloat, err := typed.Float64(); err == nil && !math.IsNaN(asFloat) && !math.IsInf(asFloat, 0) {
			return asFloat, true
		}
		return nil, false
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			clean, ok := sanitizeJiraIssueFieldsValue(item)
			if !ok {
				continue
			}
			out = append(out, clean)
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case map[string]any:
		if len(typed) == 0 {
			return nil, false
		}
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			cleanKey := strings.TrimSpace(key)
			if cleanKey == "" {
				continue
			}
			clean, ok := sanitizeJiraIssueFieldsValue(item)
			if !ok {
				continue
			}
			out[cleanKey] = clean
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

func sanitizeJiraIssueFieldsMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		cleanKey := strings.TrimSpace(key)
		if cleanKey == "" {
			continue
		}
		clean, ok := sanitizeJiraIssueFieldsValue(value)
		if !ok {
			continue
		}
		out[cleanKey] = clean
	}
	return out
}

func clampJiraEntityRetryAttempts(value int) int {
	if value < JiraDeliveryRetryAttemptsMin {
		return JiraDeliveryRetryAttemptsDefault
	}
	if value > JiraDeliveryRetryAttemptsMax {
		return JiraDeliveryRetryAttemptsMax
	}
	return value
}

func clampJiraEntityRetryBackoffSeconds(value int) int {
	if value < JiraDeliveryRetryBackoffSecondsMin {
		return JiraDeliveryRetryBackoffSecondsDefault
	}
	if value > JiraDeliveryRetryBackoffSecondsMax {
		return JiraDeliveryRetryBackoffSecondsMax
	}
	return value
}

func decodeStringListJSON(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return sanitizeJiraStringList(out), nil
}

func decodeStringMapJSON(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return map[string]string{}, nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return sanitizeSeverityPriorityMapping(out), nil
}

func decodeAnyMapJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return map[string]any{}, nil
	}
	return sanitizeJiraIssueFieldsMap(out), nil
}

func scanJiraEntitySettingsRow(scanner interface {
	Scan(dest ...any) error
}) (*JiraEntitySettings, error) {
	var item JiraEntitySettings
	var resolveTransitionName sql.NullString
	var openTransitionName sql.NullString
	var labelsRaw []byte
	var componentsRaw []byte
	var priorityRaw []byte
	var issueFieldsRaw []byte

	if err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.ConfigLevel,
		&item.ConfigTargetID,
		&item.IsEnabled,
		&item.JiraProjectKey,
		&item.IssueType,
		&item.DeliveryRetryAttempts,
		&item.DeliveryRetryBackoffSeconds,
		&openTransitionName,
		&resolveTransitionName,
		&issueFieldsRaw,
		&labelsRaw,
		&componentsRaw,
		&priorityRaw,
		&item.TicketSummaryTemplate,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if openTransitionName.Valid {
		item.OpenTransitionName = strings.TrimSpace(openTransitionName.String)
	}
	if resolveTransitionName.Valid {
		item.ResolveTransitionName = strings.TrimSpace(resolveTransitionName.String)
	}
	item.JiraProjectKey = strings.TrimSpace(item.JiraProjectKey)
	item.IssueType = strings.TrimSpace(item.IssueType)
	item.TicketSummaryTemplate = strings.TrimSpace(item.TicketSummaryTemplate)
	item.DeliveryRetryAttempts = clampJiraEntityRetryAttempts(item.DeliveryRetryAttempts)
	item.DeliveryRetryBackoffSeconds = clampJiraEntityRetryBackoffSeconds(item.DeliveryRetryBackoffSeconds)

	var err error
	if item.Labels, err = decodeStringListJSON(labelsRaw); err != nil {
		return nil, err
	}
	if item.Components, err = decodeStringListJSON(componentsRaw); err != nil {
		return nil, err
	}
	if item.SeverityToPriorityMapping, err = decodeStringMapJSON(priorityRaw); err != nil {
		return nil, err
	}
	if item.IssueFields, err = decodeAnyMapJSON(issueFieldsRaw); err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *PostgresStore) GetJiraEntitySettings(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID) (*JiraEntitySettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || configTargetID == uuid.Nil || normalizeJiraConfigLevel(string(configLevel)) == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
SELECT
  id, project_id, config_level, config_target_id, is_enabled,
  jira_project_key, issue_type, delivery_retry_attempts, delivery_retry_backoff_seconds,
  open_transition_name, resolve_transition_name, issue_fields_json,
  labels, components, severity_to_priority_mapping, ticket_summary_template, created_at, updated_at
FROM jira_entity_settings
WHERE project_id = $1 AND config_level = $2 AND config_target_id = $3
LIMIT 1
`, projectID, string(configLevel), configTargetID)
	item, err := scanJiraEntitySettingsRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) UpsertJiraEntitySettings(input JiraEntitySettingsUpsertInput) (*JiraEntitySettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	level := normalizeJiraConfigLevel(string(input.ConfigLevel))
	if input.ProjectID == uuid.Nil || input.ConfigTargetID == uuid.Nil || level == "" {
		return nil, ErrInvalidPayload
	}

	input.ConfigLevel = level
	input.JiraProjectKey = strings.TrimSpace(input.JiraProjectKey)
	input.IssueType = strings.TrimSpace(input.IssueType)
	input.OpenTransitionName = strings.TrimSpace(input.OpenTransitionName)
	input.ResolveTransitionName = strings.TrimSpace(input.ResolveTransitionName)
	input.TicketSummaryTemplate = strings.TrimSpace(input.TicketSummaryTemplate)
	input.DeliveryRetryAttempts = clampJiraEntityRetryAttempts(input.DeliveryRetryAttempts)
	input.DeliveryRetryBackoffSeconds = clampJiraEntityRetryBackoffSeconds(input.DeliveryRetryBackoffSeconds)
	input.IssueFields = sanitizeJiraIssueFieldsMap(input.IssueFields)
	input.Labels = sanitizeJiraStringList(input.Labels)
	input.Components = sanitizeJiraStringList(input.Components)
	input.SeverityToPriorityMapping = sanitizeSeverityPriorityMapping(input.SeverityToPriorityMapping)

	labelsRaw, err := json.Marshal(input.Labels)
	if err != nil {
		return nil, err
	}
	componentsRaw, err := json.Marshal(input.Components)
	if err != nil {
		return nil, err
	}
	priorityRaw, err := json.Marshal(input.SeverityToPriorityMapping)
	if err != nil {
		return nil, err
	}
	issueFieldsRaw, err := json.Marshal(input.IssueFields)
	if err != nil {
		return nil, err
	}
	if !json.Valid(issueFieldsRaw) {
		return nil, fmt.Errorf("invalid issue fields json")
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx, `
INSERT INTO jira_entity_settings (
  project_id, config_level, config_target_id, is_enabled,
  jira_project_key, issue_type, delivery_retry_attempts, delivery_retry_backoff_seconds,
  open_transition_name, resolve_transition_name, issue_fields_json,
  labels, components, severity_to_priority_mapping, ticket_summary_template, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), NULLIF($10, ''), $11, $12, $13, $14, $15, NOW(), NOW())
ON CONFLICT (project_id, config_level, config_target_id) DO UPDATE
SET is_enabled = EXCLUDED.is_enabled,
    jira_project_key = EXCLUDED.jira_project_key,
    issue_type = EXCLUDED.issue_type,
    delivery_retry_attempts = EXCLUDED.delivery_retry_attempts,
    delivery_retry_backoff_seconds = EXCLUDED.delivery_retry_backoff_seconds,
    open_transition_name = EXCLUDED.open_transition_name,
    resolve_transition_name = EXCLUDED.resolve_transition_name,
    issue_fields_json = EXCLUDED.issue_fields_json,
    labels = EXCLUDED.labels,
    components = EXCLUDED.components,
    severity_to_priority_mapping = EXCLUDED.severity_to_priority_mapping,
    ticket_summary_template = EXCLUDED.ticket_summary_template,
    updated_at = NOW()
RETURNING
  id, project_id, config_level, config_target_id, is_enabled,
  jira_project_key, issue_type, delivery_retry_attempts, delivery_retry_backoff_seconds,
  open_transition_name, resolve_transition_name, issue_fields_json,
  labels, components, severity_to_priority_mapping, ticket_summary_template, created_at, updated_at
`, input.ProjectID, string(input.ConfigLevel), input.ConfigTargetID, input.IsEnabled,
		input.JiraProjectKey, input.IssueType, input.DeliveryRetryAttempts, input.DeliveryRetryBackoffSeconds,
		input.OpenTransitionName, input.ResolveTransitionName, issueFieldsRaw,
		labelsRaw, componentsRaw, priorityRaw, input.TicketSummaryTemplate)

	item, err := scanJiraEntitySettingsRow(row)
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) ResolveEffectiveJiraSettings(input JiraEffectiveSettingsResolveInput) (*JiraEffectiveSettings, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if input.ProjectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	candidates := make([]struct {
		level JiraConfigLevel
		id    *uuid.UUID
	}, 0, 3)
	candidates = append(candidates, struct {
		level JiraConfigLevel
		id    *uuid.UUID
	}{level: JiraConfigLevelTest, id: input.TestID})
	candidates = append(candidates, struct {
		level JiraConfigLevel
		id    *uuid.UUID
	}{level: JiraConfigLevelScope, id: input.ScopeID})
	candidates = append(candidates, struct {
		level JiraConfigLevel
		id    *uuid.UUID
	}{level: JiraConfigLevelProduct, id: input.ProductID})

	for _, candidate := range candidates {
		if candidate.id == nil || *candidate.id == uuid.Nil {
			continue
		}
		item, err := s.GetJiraEntitySettings(input.ProjectID, candidate.level, *candidate.id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !item.IsEnabled {
			continue
		}
		if strings.TrimSpace(item.JiraProjectKey) == "" || strings.TrimSpace(item.IssueType) == "" {
			continue
		}
		return &JiraEffectiveSettings{
			ResolvedFromLevel: candidate.level,
			ResolvedTargetID:  *candidate.id,
			Settings:          *item,
		}, nil
	}
	return nil, ErrNotFound
}

func scanJiraIssueMappingRow(scanner interface {
	Scan(dest ...any) error
}) (*JiraIssueMapping, error) {
	var item JiraIssueMapping
	var dedupRuleID uuid.NullUUID
	var testID uuid.NullUUID
	var componentPURL sql.NullString
	var effectiveConfigLevel sql.NullString
	var effectiveConfigTargetID uuid.NullUUID
	var jiraIssueKey sql.NullString
	var jiraIssueID sql.NullString
	var lastSyncedAt sql.NullTime
	var lastError sql.NullString
	var closedAt sql.NullTime

	if err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.ConfigLevel,
		&item.ConfigTargetID,
		&item.AlertGroupID,
		&dedupRuleID,
		&testID,
		&componentPURL,
		&effectiveConfigLevel,
		&effectiveConfigTargetID,
		&jiraIssueKey,
		&jiraIssueID,
		&item.Status,
		&lastSyncedAt,
		&lastError,
		&closedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if dedupRuleID.Valid {
		value := dedupRuleID.UUID
		item.DedupRuleID = &value
	}
	if testID.Valid {
		value := testID.UUID
		item.TestID = &value
	}
	if componentPURL.Valid {
		item.ComponentPURL = strings.TrimSpace(componentPURL.String)
	}
	if effectiveConfigLevel.Valid {
		level := normalizeJiraConfigLevel(effectiveConfigLevel.String)
		if level != "" {
			item.EffectiveConfigLevel = &level
		}
	}
	if effectiveConfigTargetID.Valid {
		value := effectiveConfigTargetID.UUID
		item.EffectiveConfigTargetID = &value
	}
	if jiraIssueKey.Valid {
		item.JiraIssueKey = strings.TrimSpace(jiraIssueKey.String)
	}
	if jiraIssueID.Valid {
		item.JiraIssueID = strings.TrimSpace(jiraIssueID.String)
	}
	item.LastSyncedAt = nullTimePtr(lastSyncedAt)
	if lastError.Valid {
		item.LastError = strings.TrimSpace(lastError.String)
	}
	item.ClosedAt = nullTimePtr(closedAt)
	return &item, nil
}

func (s *PostgresStore) ListOpenJiraIssueMappings(projectID, alertGroupID uuid.UUID, dedupRuleID *uuid.UUID) ([]JiraIssueMapping, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || alertGroupID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	query := `
SELECT
  id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  test_id, component_purl, effective_config_level, effective_config_target_id,
  jira_issue_key, jira_issue_id, status, last_synced_at, last_error, closed_at, created_at, updated_at
FROM jira_issue_mappings
WHERE project_id = $1
  AND alert_group_id = $2
  AND status = 'OPEN'
`
	args := []any{projectID, alertGroupID}
	if dedupRuleID == nil {
		// Any dedup-rule binding.
	} else if *dedupRuleID == uuid.Nil {
		query += " AND dedup_rule_id IS NULL\n"
	} else {
		query += " AND dedup_rule_id = $3\n"
		args = append(args, *dedupRuleID)
	}
	query += "ORDER BY updated_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]JiraIssueMapping, 0, 8)
	for rows.Next() {
		item, scanErr := scanJiraIssueMappingRow(rows)
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

func (s *PostgresStore) UpsertJiraIssueMapping(input JiraIssueMappingUpsertInput) (*JiraIssueMapping, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	level := normalizeJiraConfigLevel(string(input.ConfigLevel))
	status := normalizeJiraIssueMappingStatus(string(input.Status))
	if input.ProjectID == uuid.Nil || input.ConfigTargetID == uuid.Nil || input.AlertGroupID == uuid.Nil || level == "" || status == "" {
		return nil, ErrInvalidPayload
	}
	input.ConfigLevel = level
	input.Status = status
	if input.TestID != nil && *input.TestID == uuid.Nil {
		input.TestID = nil
	}
	input.ComponentPURL = strings.TrimSpace(input.ComponentPURL)
	hasComponentKey := input.TestID != nil && input.ComponentPURL != ""
	if (input.TestID == nil) != (input.ComponentPURL == "") {
		return nil, ErrInvalidPayload
	}
	if input.EffectiveConfigLevel != nil {
		effectiveLevel := normalizeJiraConfigLevel(string(*input.EffectiveConfigLevel))
		if effectiveLevel == "" {
			return nil, ErrInvalidPayload
		}
		input.EffectiveConfigLevel = &effectiveLevel
	}
	if input.EffectiveConfigTargetID != nil && *input.EffectiveConfigTargetID == uuid.Nil {
		input.EffectiveConfigTargetID = nil
	}
	input.JiraIssueKey = strings.TrimSpace(input.JiraIssueKey)
	input.JiraIssueID = strings.TrimSpace(input.JiraIssueID)
	input.LastError = strings.TrimSpace(input.LastError)
	if len(input.LastError) > 2048 {
		input.LastError = input.LastError[:2048]
	}
	if input.DedupRuleID != nil && *input.DedupRuleID == uuid.Nil {
		input.DedupRuleID = nil
	}

	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		ctx, cancel := s.ctx()
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			cancel()
			return nil, err
		}

		rolledBack := false
		rollback := func() {
			if rolledBack {
				return
			}
			rolledBack = true
			_ = tx.Rollback()
		}

		var existingID uuid.UUID
		if hasComponentKey {
			err = tx.QueryRowContext(ctx, `
SELECT id
FROM jira_issue_mappings
WHERE project_id = $1
  AND test_id = $2
  AND component_purl = $3
ORDER BY updated_at DESC
LIMIT 1
FOR UPDATE
`, input.ProjectID, *input.TestID, input.ComponentPURL).Scan(&existingID)
		} else {
			err = tx.QueryRowContext(ctx, `
SELECT id
FROM jira_issue_mappings
WHERE project_id = $1
  AND config_level = $2
  AND config_target_id = $3
  AND alert_group_id = $4
  AND (($5::uuid IS NULL AND dedup_rule_id IS NULL) OR dedup_rule_id = $5::uuid)
LIMIT 1
FOR UPDATE
`, input.ProjectID, string(input.ConfigLevel), input.ConfigTargetID, input.AlertGroupID, input.DedupRuleID).Scan(&existingID)
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			rollback()
			cancel()
			return nil, err
		}

		if errors.Is(err, sql.ErrNoRows) {
			row := tx.QueryRowContext(ctx, `
INSERT INTO jira_issue_mappings (
  project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  test_id, component_purl, effective_config_level, effective_config_target_id,
  jira_issue_key, jira_issue_id, status, last_synced_at, last_error, closed_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12, $13, NULLIF($14, ''), $15, NOW(), NOW())
RETURNING
  id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  test_id, component_purl, effective_config_level, effective_config_target_id,
  jira_issue_key, jira_issue_id, status, last_synced_at, last_error, closed_at, created_at, updated_at
`, input.ProjectID, string(input.ConfigLevel), input.ConfigTargetID, input.AlertGroupID, input.DedupRuleID,
				input.TestID, input.ComponentPURL, input.EffectiveConfigLevel, input.EffectiveConfigTargetID,
				input.JiraIssueKey, input.JiraIssueID, string(input.Status), input.LastSyncedAt, input.LastError, input.ClosedAt)
			item, scanErr := scanJiraIssueMappingRow(row)
			if scanErr != nil {
				rollback()
				cancel()
				if isUniqueViolation(scanErr) && attempt < maxAttempts-1 {
					// Concurrent insert won race: retry in a fresh transaction.
					continue
				}
				return nil, scanErr
			}
			if err := tx.Commit(); err != nil {
				rollback()
				cancel()
				return nil, err
			}
			cancel()
			return item, nil
		}

		row := tx.QueryRowContext(ctx, `
UPDATE jira_issue_mappings
SET config_level = $2,
    config_target_id = $3,
    alert_group_id = $4,
    dedup_rule_id = $5,
    test_id = $6,
    component_purl = NULLIF($7, ''),
    effective_config_level = $8,
    effective_config_target_id = $9,
    jira_issue_key = NULLIF($10, ''),
    jira_issue_id = NULLIF($11, ''),
    status = $12,
    last_synced_at = $13,
    last_error = NULLIF($14, ''),
    closed_at = $15,
    updated_at = NOW()
WHERE id = $1
RETURNING
  id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  test_id, component_purl, effective_config_level, effective_config_target_id,
  jira_issue_key, jira_issue_id, status, last_synced_at, last_error, closed_at, created_at, updated_at
`, existingID,
			string(input.ConfigLevel), input.ConfigTargetID, input.AlertGroupID, input.DedupRuleID,
			input.TestID, input.ComponentPURL, input.EffectiveConfigLevel, input.EffectiveConfigTargetID,
			input.JiraIssueKey, input.JiraIssueID, string(input.Status), input.LastSyncedAt, input.LastError, input.ClosedAt)
		item, err := scanJiraIssueMappingRow(row)
		if err != nil {
			rollback()
			cancel()
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			rollback()
			cancel()
			return nil, err
		}
		cancel()
		return item, nil
	}

	return nil, fmt.Errorf("upsert jira issue mapping exceeded retry budget")
}

func (s *PostgresStore) GetLatestJiraIssueMappingForComponent(projectID, testID uuid.UUID, componentPURL string) (*JiraIssueMapping, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil || testID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	componentPURL = strings.TrimSpace(componentPURL)
	if componentPURL == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
SELECT
  id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  test_id, component_purl, effective_config_level, effective_config_target_id,
  jira_issue_key, jira_issue_id, status, last_synced_at, last_error, closed_at, created_at, updated_at
FROM jira_issue_mappings
WHERE project_id = $1
  AND test_id = $2
  AND component_purl = $3
ORDER BY updated_at DESC
LIMIT 1
`, projectID, testID, componentPURL)
	item, err := scanJiraIssueMappingRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) InsertJiraDeliveryAttempt(input JiraDeliveryAttemptInput) error {
	if s == nil {
		return errors.New("store is nil")
	}
	action := normalizeJiraDeliveryAction(string(input.Action))
	outcome := normalizeJiraDeliveryOutcome(string(input.Outcome))
	if input.ProjectID == uuid.Nil || action == "" || outcome == "" {
		return ErrInvalidPayload
	}
	if input.AttemptNo < 1 {
		input.AttemptNo = 1
	}
	if input.ConfigLevel != nil {
		normalized := normalizeJiraConfigLevel(string(*input.ConfigLevel))
		if normalized == "" {
			return ErrInvalidPayload
		}
		input.ConfigLevel = &normalized
	}
	input.ErrorCode = strings.TrimSpace(input.ErrorCode)
	input.ErrorMessage = strings.TrimSpace(input.ErrorMessage)
	if len(input.ErrorCode) > 128 {
		input.ErrorCode = input.ErrorCode[:128]
	}
	if len(input.ErrorMessage) > 2048 {
		input.ErrorMessage = input.ErrorMessage[:2048]
	}

	ctx, cancel := s.ctx()
	defer cancel()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO jira_delivery_attempts (
  queue_job_id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  jira_issue_mapping_id, attempt_no, action, outcome, http_status, error_code, error_message, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, ''), NULLIF($13, ''), NOW())
	`, input.QueueJobID, input.ProjectID, input.ConfigLevel, input.ConfigTargetID, input.AlertGroupID, input.DedupRuleID,
		input.JiraIssueMappingID, input.AttemptNo, string(action), string(outcome), input.HTTPStatus, input.ErrorCode, input.ErrorMessage)
	return err
}

func (s *PostgresStore) ListJiraIssueMappingsByEntity(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID, filter JiraIssueMappingsListFilter) ([]JiraIssueMapping, int, error) {
	if s == nil {
		return nil, 0, errors.New("store is nil")
	}
	level := normalizeJiraConfigLevel(string(configLevel))
	if projectID == uuid.Nil || configTargetID == uuid.Nil || level == "" {
		return nil, 0, ErrInvalidPayload
	}
	limit := filter.Limit
	offset := filter.Offset
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	status := strings.ToUpper(strings.TrimSpace(filter.Status))
	if status == "" {
		status = "OPEN"
	}
	if status != "OPEN" && status != "CLOSED" && status != "ALL" {
		return nil, 0, ErrInvalidPayload
	}
	component := strings.TrimSpace(filter.Component)
	jiraKey := strings.TrimSpace(filter.JiraKey)
	ctx, cancel := s.ctx()
	defer cancel()

	// For TEST/SCOPE/PRODUCT screens this includes mappings created by effective precedence
	// (e.g. PRODUCT config used for TEST occurrence) and rows with nullable component/test references.
	baseWhere := []string{
		"m.project_id = $1",
	}
	args := []any{projectID, configTargetID}
	argN := 3

	contextSQL := ""
	switch level {
	case JiraConfigLevelProduct:
		contextSQL = `(
			(m.config_level = 'PRODUCT' AND m.config_target_id = $2)
			OR (
				m.config_level = 'SCOPE'
				AND EXISTS (
					SELECT 1
					FROM scopes s
					WHERE s.id = m.config_target_id
					  AND s.product_id = $2
				)
			)
			OR (
				m.config_level = 'TEST'
				AND EXISTS (
					SELECT 1
					FROM tests t
					JOIN scopes s ON s.id = t.scope_id
					WHERE t.id = m.config_target_id
					  AND s.product_id = $2
				)
			)
			OR (
				m.test_id IS NOT NULL
				AND EXISTS (
					SELECT 1
					FROM tests t
					JOIN scopes s ON s.id = t.scope_id
					WHERE t.id = m.test_id
					  AND s.product_id = $2
				)
			)
			OR EXISTS (
				SELECT 1
				FROM alert_occurrences ao
				WHERE ao.project_id = m.project_id
				  AND ao.group_id = m.alert_group_id
				  AND ao.product_id = $2
			)
		)`
	case JiraConfigLevelScope:
		contextSQL = `(
			(m.config_level = 'SCOPE' AND m.config_target_id = $2)
			OR (
				m.config_level = 'TEST'
				AND EXISTS (
					SELECT 1
					FROM tests t
					WHERE t.id = m.config_target_id
					  AND t.scope_id = $2
				)
			)
			OR (m.test_id IS NOT NULL AND EXISTS (
				SELECT 1
				FROM tests t
				WHERE t.id = m.test_id
				  AND t.scope_id = $2
			))
			OR EXISTS (
				SELECT 1
				FROM alert_occurrences ao
				WHERE ao.project_id = m.project_id
				  AND ao.group_id = m.alert_group_id
				  AND ao.scope_id = $2
			)
		)`
	case JiraConfigLevelTest:
		contextSQL = `(
			(m.config_level = 'TEST' AND m.config_target_id = $2)
			OR m.test_id = $2
			OR EXISTS (
				SELECT 1
				FROM alert_occurrences ao
				WHERE ao.project_id = m.project_id
				  AND ao.group_id = m.alert_group_id
				  AND ao.test_id = $2
			)
		)`
	default:
		return nil, 0, ErrInvalidPayload
	}
	baseWhere = append(baseWhere, contextSQL)

	if status != "ALL" {
		baseWhere = append(baseWhere, fmt.Sprintf("m.status = $%d", argN))
		args = append(args, status)
		argN++
	}
	if component != "" {
		baseWhere = append(baseWhere, fmt.Sprintf("LOWER(COALESCE(m.component_purl,'')) LIKE LOWER($%d)", argN))
		args = append(args, "%"+component+"%")
		argN++
	}
	if jiraKey != "" {
		baseWhere = append(baseWhere, fmt.Sprintf("(LOWER(COALESCE(m.jira_issue_key,'')) LIKE LOWER($%d) OR LOWER(COALESCE(m.jira_issue_id,'')) LIKE LOWER($%d))", argN, argN))
		args = append(args, "%"+jiraKey+"%")
		argN++
	}
	whereSQL := strings.Join(baseWhere, " AND ")

	var total int
	countSQL := `
SELECT COUNT(*)
FROM jira_issue_mappings m
WHERE ` + whereSQL
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	itemsSQL := `
SELECT
  m.id, m.project_id, m.config_level, m.config_target_id, m.alert_group_id, m.dedup_rule_id,
  m.test_id, m.component_purl, m.effective_config_level, m.effective_config_target_id,
  m.jira_issue_key, m.jira_issue_id, m.status, m.last_synced_at, m.last_error, m.closed_at, m.created_at, m.updated_at
FROM jira_issue_mappings m
WHERE ` + whereSQL + `
ORDER BY m.updated_at DESC
LIMIT $` + fmt.Sprintf("%d", argN) + ` OFFSET $` + fmt.Sprintf("%d", argN+1)
	argsItems := append(append([]any{}, args...), limit, offset)
	rows, err := s.db.QueryContext(ctx, itemsSQL, argsItems...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]JiraIssueMapping, 0, limit)
	for rows.Next() {
		item, scanErr := scanJiraIssueMappingRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func scanJiraDeliveryAttemptRow(scanner interface {
	Scan(dest ...any) error
}) (*JiraDeliveryAttempt, error) {
	var item JiraDeliveryAttempt
	var queueJobID uuid.NullUUID
	var configLevel sql.NullString
	var configTargetID uuid.NullUUID
	var alertGroupID uuid.NullUUID
	var dedupRuleID uuid.NullUUID
	var mappingID uuid.NullUUID
	var httpStatus sql.NullInt32
	var errorCode sql.NullString
	var errorMessage sql.NullString
	if err := scanner.Scan(
		&item.ID,
		&queueJobID,
		&item.ProjectID,
		&configLevel,
		&configTargetID,
		&alertGroupID,
		&dedupRuleID,
		&mappingID,
		&item.AttemptNo,
		&item.Action,
		&item.Outcome,
		&httpStatus,
		&errorCode,
		&errorMessage,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	if queueJobID.Valid {
		value := queueJobID.UUID
		item.QueueJobID = &value
	}
	if configLevel.Valid {
		value := normalizeJiraConfigLevel(configLevel.String)
		if value != "" {
			item.ConfigLevel = &value
		}
	}
	if configTargetID.Valid {
		value := configTargetID.UUID
		item.ConfigTargetID = &value
	}
	if alertGroupID.Valid {
		value := alertGroupID.UUID
		item.AlertGroupID = &value
	}
	if dedupRuleID.Valid {
		value := dedupRuleID.UUID
		item.DedupRuleID = &value
	}
	if mappingID.Valid {
		value := mappingID.UUID
		item.JiraIssueMappingID = &value
	}
	if httpStatus.Valid {
		value := int(httpStatus.Int32)
		item.HTTPStatus = &value
	}
	if errorCode.Valid {
		item.ErrorCode = strings.TrimSpace(errorCode.String)
	}
	if errorMessage.Valid {
		item.ErrorMessage = strings.TrimSpace(errorMessage.String)
	}
	return &item, nil
}

func (s *PostgresStore) ListJiraDeliveryAttemptsByEntity(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID, limit, offset int) ([]JiraDeliveryAttempt, int, error) {
	if s == nil {
		return nil, 0, errors.New("store is nil")
	}
	level := normalizeJiraConfigLevel(string(configLevel))
	if projectID == uuid.Nil || configTargetID == uuid.Nil || level == "" {
		return nil, 0, ErrInvalidPayload
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	ctx, cancel := s.ctx()
	defer cancel()

	var total int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM jira_delivery_attempts
WHERE project_id = $1 AND config_level = $2 AND config_target_id = $3
`, projectID, string(level), configTargetID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT
  id, queue_job_id, project_id, config_level, config_target_id, alert_group_id, dedup_rule_id,
  jira_issue_mapping_id, attempt_no, action, outcome, http_status, error_code, error_message, created_at
FROM jira_delivery_attempts
WHERE project_id = $1
  AND config_level = $2
  AND config_target_id = $3
ORDER BY created_at DESC
LIMIT $4 OFFSET $5
`, projectID, string(level), configTargetID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]JiraDeliveryAttempt, 0, limit)
	for rows.Next() {
		item, scanErr := scanJiraDeliveryAttemptRow(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

func scanJiraMetadataCacheRow(scanner interface {
	Scan(dest ...any) error
}) (*JiraMetadataCacheEntry, error) {
	var item JiraMetadataCacheEntry
	var payloadRaw []byte
	if err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.BaseURLHash,
		&item.MetadataType,
		&item.MetadataScopeKey,
		&payloadRaw,
		&item.FetchedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	item.BaseURLHash = strings.TrimSpace(item.BaseURLHash)
	item.MetadataScopeKey = strings.TrimSpace(item.MetadataScopeKey)
	if len(payloadRaw) == 0 {
		payloadRaw = []byte("[]")
	}
	item.PayloadJSON = append(item.PayloadJSON[:0], payloadRaw...)
	return &item, nil
}

func (s *PostgresStore) GetJiraMetadataCache(projectID uuid.UUID, baseURLHash string, metadataType JiraMetadataType, metadataScopeKey string) (*JiraMetadataCacheEntry, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	baseURLHash = strings.TrimSpace(baseURLHash)
	scopeKey := strings.TrimSpace(metadataScopeKey)
	metaType := normalizeJiraMetadataType(string(metadataType))
	if projectID == uuid.Nil || baseURLHash == "" || metaType == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
SELECT
  id, project_id, base_url_hash, metadata_type, metadata_scope_key, payload_json, fetched_at, created_at, updated_at
FROM jira_metadata_cache
WHERE project_id = $1
  AND base_url_hash = $2
  AND metadata_type = $3
  AND metadata_scope_key = $4
LIMIT 1
`, projectID, baseURLHash, string(metaType), scopeKey)
	item, err := scanJiraMetadataCacheRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) UpsertJiraMetadataCache(input JiraMetadataCacheUpsertInput) (*JiraMetadataCacheEntry, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	metaType := normalizeJiraMetadataType(string(input.MetadataType))
	input.BaseURLHash = strings.TrimSpace(input.BaseURLHash)
	input.MetadataScopeKey = strings.TrimSpace(input.MetadataScopeKey)
	if input.ProjectID == uuid.Nil || input.BaseURLHash == "" || metaType == "" {
		return nil, ErrInvalidPayload
	}
	payload := input.PayloadJSON
	if len(payload) == 0 {
		payload = []byte("[]")
	}
	if !json.Valid(payload) {
		return nil, ErrInvalidPayload
	}
	fetchedAt := time.Now().UTC()
	if input.FetchedAt != nil && !input.FetchedAt.IsZero() {
		fetchedAt = input.FetchedAt.UTC()
	}

	ctx, cancel := s.ctx()
	defer cancel()
	row := s.db.QueryRowContext(ctx, `
INSERT INTO jira_metadata_cache (
  project_id, base_url_hash, metadata_type, metadata_scope_key, payload_json, fetched_at, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
ON CONFLICT (project_id, base_url_hash, metadata_type, metadata_scope_key) DO UPDATE
SET payload_json = EXCLUDED.payload_json,
    fetched_at = EXCLUDED.fetched_at,
    updated_at = NOW()
RETURNING
  id, project_id, base_url_hash, metadata_type, metadata_scope_key, payload_json, fetched_at, created_at, updated_at
`, input.ProjectID, input.BaseURLHash, string(metaType), input.MetadataScopeKey, payload, fetchedAt)
	item, err := scanJiraMetadataCacheRow(row)
	if err != nil {
		return nil, err
	}
	return item, nil
}
