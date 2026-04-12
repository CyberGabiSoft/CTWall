package store

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
)

func (s *PostgresStore) ensureAlertDetectionModesDefaultsCtx(ctx context.Context, projectID uuid.UUID) error {
	if projectID == uuid.Nil {
		return ErrInvalidPayload
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
INSERT INTO alert_detection_modes (project_id, mode, enabled, severity, lookback_days, created_at, updated_at)
SELECT $1::uuid, d.mode, d.enabled, d.severity, d.lookback_days, $2, $2
FROM (
  VALUES
    ('PURL_VERSION_SMART'::text, TRUE,  'ERROR'::text, NULL::integer),
    ('PURL_CONTAINS_PREFIX'::text, FALSE, 'WARN'::text, NULL::integer)
) AS d(mode, enabled, severity, lookback_days)
ON CONFLICT (project_id, mode) DO NOTHING
`, projectID, now)
	return err
}

func (s *PostgresStore) listAlertDetectionModesCtx(ctx context.Context, projectID uuid.UUID) ([]models.AlertDetectionMode, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, project_id, mode, enabled, severity, lookback_days, created_at, updated_at
FROM alert_detection_modes
WHERE project_id = $1
ORDER BY CASE mode
  WHEN 'PURL_VERSION_SMART' THEN 1
  WHEN 'PURL_CONTAINS_PREFIX' THEN 2
  ELSE 100
END, mode ASC
`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]models.AlertDetectionMode, 0, 2)
	for rows.Next() {
		var item models.AlertDetectionMode
		var lookbackDays sql.NullInt32
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.Mode,
			&item.Enabled,
			&item.Severity,
			&lookbackDays,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if lookbackDays.Valid {
			value := int(lookbackDays.Int32)
			item.LookbackDays = &value
		} else {
			item.LookbackDays = nil
		}
		item.Mode = strings.ToUpper(strings.TrimSpace(item.Mode))
		item.Severity = strings.ToUpper(strings.TrimSpace(item.Severity))
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *PostgresStore) resolveAlertDetectionModeConfigCtx(ctx context.Context, projectID uuid.UUID, mode AlertDetectionMode) (*models.AlertDetectionMode, error) {
	mode = normalizeAlertDetectionMode(string(mode))
	if mode == AlertDetectionMode("") {
		mode = AlertDetectionModePURLVersionSmart
	}
	if err := s.ensureAlertDetectionModesDefaultsCtx(ctx, projectID); err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, project_id, mode, enabled, severity, lookback_days, created_at, updated_at
FROM alert_detection_modes
WHERE project_id = $1 AND mode = $2
LIMIT 1
`, projectID, string(mode))
	var item models.AlertDetectionMode
	var lookbackDays sql.NullInt32
	if err := row.Scan(
		&item.ID,
		&item.ProjectID,
		&item.Mode,
		&item.Enabled,
		&item.Severity,
		&lookbackDays,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Defensive fallback; defaults should exist after ensure.
			fallback := models.AlertDetectionMode{
				ID:           uuid.Nil,
				ProjectID:    projectID,
				Mode:         string(mode),
				Enabled:      true,
				Severity:     string(eventmeta.SeverityError),
				LookbackDays: nil,
			}
			if mode == AlertDetectionModePURLContainsPrefix {
				fallback.Enabled = false
				fallback.Severity = string(eventmeta.SeverityWarn)
			}
			return &fallback, nil
		}
		return nil, err
	}
	if lookbackDays.Valid {
		value := int(lookbackDays.Int32)
		item.LookbackDays = &value
	} else {
		item.LookbackDays = nil
	}
	item.Mode = strings.ToUpper(strings.TrimSpace(item.Mode))
	item.Severity = strings.ToUpper(strings.TrimSpace(item.Severity))
	return &item, nil
}

func (s *PostgresStore) ListAlertDetectionModes(projectID uuid.UUID) ([]models.AlertDetectionMode, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureAlertDetectionModesDefaultsCtx(ctx, projectID); err != nil {
		return nil, err
	}
	return s.listAlertDetectionModesCtx(ctx, projectID)
}

func (s *PostgresStore) ReplaceAlertDetectionModes(projectID uuid.UUID, inputs []AlertDetectionModeInput) ([]models.AlertDetectionMode, error) {
	if s == nil {
		return nil, errors.New("store is nil")
	}
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	normalized := make(map[AlertDetectionMode]AlertDetectionModeInput, 2)
	for _, item := range defaultAlertDetectionModeInputs() {
		normalized[item.Mode] = item
	}
	for _, item := range inputs {
		mode := normalizeAlertDetectionMode(string(item.Mode))
		if mode == AlertDetectionMode("") {
			return nil, ErrInvalidPayload
		}
		severity := normalizeAlertDetectionSeverity(string(item.Severity))
		if severity == eventmeta.Severity("") || !eventmeta.ValidSeverity(string(severity)) {
			return nil, ErrInvalidPayload
		}
		lookbackDays := normalizeAlertDetectionLookbackDays(item.LookbackDays)
		if mode != AlertDetectionModePURLContainsPrefix {
			lookbackDays = nil
		}
		if lookbackDays != nil && *lookbackDays <= 0 {
			return nil, ErrInvalidPayload
		}
		normalized[mode] = AlertDetectionModeInput{
			Mode:         mode,
			Enabled:      item.Enabled,
			Severity:     severity,
			LookbackDays: lookbackDays,
		}
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
INSERT INTO alert_detection_modes (project_id, mode, enabled, severity, lookback_days, created_at, updated_at)
SELECT $1::uuid, d.mode, d.enabled, d.severity, d.lookback_days, $2, $2
FROM (
  VALUES
    ('PURL_VERSION_SMART'::text, TRUE,  'ERROR'::text, NULL::integer),
    ('PURL_CONTAINS_PREFIX'::text, FALSE, 'WARN'::text, NULL::integer)
) AS d(mode, enabled, severity, lookback_days)
ON CONFLICT (project_id, mode) DO NOTHING
`, projectID, now); err != nil {
		return nil, err
	}

	orderedModes := make([]AlertDetectionMode, 0, len(normalized))
	for mode := range normalized {
		orderedModes = append(orderedModes, mode)
	}
	sort.Slice(orderedModes, func(i, j int) bool {
		left := normalizeAlertDetectionMode(string(orderedModes[i]))
		right := normalizeAlertDetectionMode(string(orderedModes[j]))
		leftRank := 100
		rightRank := 100
		if left == AlertDetectionModePURLVersionSmart {
			leftRank = 1
		}
		if left == AlertDetectionModePURLContainsPrefix {
			leftRank = 2
		}
		if right == AlertDetectionModePURLVersionSmart {
			rightRank = 1
		}
		if right == AlertDetectionModePURLContainsPrefix {
			rightRank = 2
		}
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return left < right
	})

	for _, mode := range orderedModes {
		item := normalized[mode]
		if _, err := tx.ExecContext(ctx, `
INSERT INTO alert_detection_modes (project_id, mode, enabled, severity, lookback_days, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $6)
ON CONFLICT (project_id, mode) DO UPDATE
SET enabled = EXCLUDED.enabled,
    severity = EXCLUDED.severity,
    lookback_days = EXCLUDED.lookback_days,
    updated_at = EXCLUDED.updated_at
`, projectID, string(item.Mode), item.Enabled, string(item.Severity), item.LookbackDays, now); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.ListAlertDetectionModes(projectID)
}

func normalizeAlertDetectionLookbackDays(raw *int) *int {
	if raw == nil {
		return nil
	}
	value := *raw
	return &value
}
