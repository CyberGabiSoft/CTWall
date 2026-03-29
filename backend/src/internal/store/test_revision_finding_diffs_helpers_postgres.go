package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
)

const (
	reimportSystemUserEmail      = "system@ctwall.local"
	reimportSystemUserName       = "system"
	reimportSystemSecretByteSize = 48
)

func nullableUUID(value *uuid.UUID) any {
	if value == nil || *value == uuid.Nil {
		return nil
	}
	return *value
}

func ptrString(value string) *string {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	return &v
}

func generateSystemAccountPasswordHash() (string, error) {
	secret := make([]byte, reimportSystemSecretByteSize)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate system actor secret: %w", err)
	}
	randomSecret := base64.RawStdEncoding.EncodeToString(secret)
	return auth.HashPassword(randomSecret)
}

func isArgon2PasswordHash(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "$argon2id$")
}

func (s *PostgresStore) ensureSystemActorID(ctx context.Context) (*uuid.UUID, error) {
	var id uuid.UUID
	var passwordHash sql.NullString
	if err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash
		 FROM users
		 WHERE LOWER(email) = LOWER($1)
		 LIMIT 1`,
		reimportSystemUserEmail,
	).Scan(&id, &passwordHash); err == nil {
		if !passwordHash.Valid || !isArgon2PasswordHash(passwordHash.String) {
			hash, hashErr := generateSystemAccountPasswordHash()
			if hashErr != nil {
				return nil, hashErr
			}
			if _, updateErr := s.db.ExecContext(ctx, `
UPDATE users
SET password_hash = $2,
    updated_at = NOW()
WHERE id = $1
`, id, hash); updateErr != nil {
				return nil, updateErr
			}
		}
		return &id, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	passwordHashValue, err := generateSystemAccountPasswordHash()
	if err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx, `
INSERT INTO users (email, password_hash, role, account_type, full_name, created_at, updated_at)
VALUES ($1, $2, 'NONE', 'SERVICE_ACCOUNT', $3, NOW(), NOW())
ON CONFLICT (email) DO UPDATE
SET password_hash = CASE
    WHEN users.password_hash IS NULL OR users.password_hash = '' OR users.password_hash NOT LIKE '$argon2id$%'
      THEN EXCLUDED.password_hash
    ELSE users.password_hash
  END,
    updated_at = NOW()
RETURNING id, password_hash
`, reimportSystemUserEmail, passwordHashValue, reimportSystemUserName)
	if err := row.Scan(&id, &passwordHash); err != nil {
		return nil, err
	}
	if !passwordHash.Valid || !isArgon2PasswordHash(passwordHash.String) {
		return nil, fmt.Errorf("system actor password hash is not argon2id")
	}
	return &id, nil
}

type reimportAuditEventInput struct {
	actorID        *uuid.UUID
	action         string
	entityType     string
	entityID       *uuid.UUID
	eventKey       string
	severity       eventmeta.Severity
	title          string
	projectID      uuid.UUID
	testID         uuid.UUID
	fromRevisionID *uuid.UUID
	toRevisionID   uuid.UUID
	extra          map[string]any
}

func (s *PostgresStore) writeReimportAuditEvent(input reimportAuditEventInput) {
	details := map[string]any{
		"category":     string(eventmeta.CategoryMalware),
		"severity":     string(input.severity),
		"min_role":     string(eventmeta.MinRoleWrite),
		"event_key":    input.eventKey,
		"project_id":   input.projectID.String(),
		"component":    reimportAuditComponent,
		"title":        input.title,
		"testId":       input.testID.String(),
		"toRevisionId": input.toRevisionID.String(),
		"fromRevisionId": func() any {
			if input.fromRevisionID == nil {
				return nil
			}
			return input.fromRevisionID.String()
		}(),
	}
	for key, value := range input.extra {
		details[key] = value
	}
	rawDetails, err := json.Marshal(details)
	if err != nil {
		slog.Error("marshal reimport audit details failed", "component", reimportAuditComponent, "error", err)
		return
	}
	if err := s.CreateAuditLog(AuditLogEntry{
		ActorID:    input.actorID,
		Action:     strings.TrimSpace(input.action),
		EntityType: strings.TrimSpace(input.entityType),
		EntityID:   input.entityID,
		Details:    rawDetails,
		IPAddress:  "",
	}); err != nil {
		slog.Error("write reimport audit event failed", "component", reimportAuditComponent, "action", input.action, "error", err)
	}
}

func scanTestRevisionChangeSummary(row scanner) (*models.TestRevisionChangeSummary, error) {
	var item models.TestRevisionChangeSummary
	var fromRevisionID sql.NullString
	var computedAt sql.NullTime
	if err := row.Scan(
		&item.ToRevisionID,
		&item.ProjectID,
		&item.TestID,
		&fromRevisionID,
		&item.AddedCount,
		&item.RemovedCount,
		&item.UnchangedCount,
		&item.ReappearedCount,
		&item.Status,
		&computedAt,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	item.Status = normalizeTestRevisionFindingDiffStatus(item.Status)
	if fromRevisionID.Valid {
		if parsed, err := uuid.Parse(strings.TrimSpace(fromRevisionID.String)); err == nil && parsed != uuid.Nil {
			item.FromRevisionID = &parsed
		}
	}
	if computedAt.Valid {
		value := computedAt.Time.UTC()
		item.ComputedAt = &value
	}
	return &item, nil
}

func scanTestRevisionChangeSummaryRow(rows *sql.Rows) (*models.TestRevisionChangeSummary, error) {
	return scanTestRevisionChangeSummary(rows)
}

func scanTestRevisionFindingDiff(row scanner) (*models.TestRevisionFindingDiff, error) {
	var item models.TestRevisionFindingDiff
	var fromRevisionID sql.NullString
	if err := row.Scan(
		&item.ID,
		&item.ProjectID,
		&item.TestID,
		&fromRevisionID,
		&item.ToRevisionID,
		&item.FindingType,
		&item.DiffType,
		&item.ComponentPURL,
		&item.MalwarePURL,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	if fromRevisionID.Valid {
		if parsed, err := uuid.Parse(strings.TrimSpace(fromRevisionID.String)); err == nil && parsed != uuid.Nil {
			item.FromRevisionID = &parsed
		}
	}
	item.FindingType = strings.ToUpper(strings.TrimSpace(item.FindingType))
	item.DiffType = normalizeTestRevisionFindingDiffType(item.DiffType)
	item.ComponentPURL = strings.TrimSpace(item.ComponentPURL)
	item.MalwarePURL = strings.TrimSpace(item.MalwarePURL)
	return &item, nil
}

func scanTestRevisionFindingDiffRow(rows *sql.Rows) (*models.TestRevisionFindingDiff, error) {
	return scanTestRevisionFindingDiff(rows)
}

func scanTestRevisionFindingDiffQueueItem(row scanner) (*models.TestRevisionFindingDiffQueueItem, error) {
	var item models.TestRevisionFindingDiffQueueItem
	var fromRevisionID sql.NullString
	var lastError sql.NullString
	var lockedAt sql.NullTime
	var lockedBy sql.NullString
	var completedAt sql.NullTime
	if err := row.Scan(
		&item.ID,
		&item.ProjectID,
		&item.TestID,
		&fromRevisionID,
		&item.ToRevisionID,
		&item.Status,
		&item.Reason,
		&item.Attempts,
		&lastError,
		&lockedAt,
		&lockedBy,
		&item.CreatedAt,
		&item.UpdatedAt,
		&completedAt,
	); err != nil {
		return nil, err
	}
	if fromRevisionID.Valid {
		if parsed, err := uuid.Parse(strings.TrimSpace(fromRevisionID.String)); err == nil && parsed != uuid.Nil {
			item.FromRevisionID = &parsed
		}
	}
	item.Status = normalizeTestRevisionFindingDiffStatus(item.Status)
	item.Reason = normalizeTestRevisionFindingDiffReason(item.Reason)
	if lastError.Valid {
		item.LastError = strings.TrimSpace(lastError.String)
	}
	if lockedAt.Valid {
		value := lockedAt.Time.UTC()
		item.LockedAt = &value
	}
	if lockedBy.Valid {
		item.LockedBy = strings.TrimSpace(lockedBy.String)
	}
	if completedAt.Valid {
		value := completedAt.Time.UTC()
		item.CompletedAt = &value
	}
	return &item, nil
}

func scanTestRevisionFindingDiffQueueRow(rows *sql.Rows) (*models.TestRevisionFindingDiffQueueItem, error) {
	return scanTestRevisionFindingDiffQueueItem(rows)
}
