package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func normalizeConnectorConfigJSON(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid([]byte(trimmed)) {
		return nil, ErrInvalidPayload
	}
	// Force object payload for connector config.
	if !strings.HasPrefix(trimmed, "{") {
		return nil, ErrInvalidPayload
	}
	return json.RawMessage(trimmed), nil
}

func scanConnectorConfigRow(row *sql.Row) (*ConnectorConfig, error) {
	var item ConnectorConfig
	var scopeID uuid.NullUUID
	var lastTestAt sql.NullTime
	var lastTestMessage sql.NullString
	if err := row.Scan(
		&item.ID,
		&item.ConnectorType,
		&item.ScopeType,
		&scopeID,
		&item.ConfigJSON,
		&item.IsEnabled,
		&item.LastTestStatus,
		&lastTestAt,
		&lastTestMessage,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if scopeID.Valid {
		id := scopeID.UUID
		item.ScopeID = &id
	}
	item.LastTestAt = nullTimePtr(lastTestAt)
	if lastTestMessage.Valid {
		item.LastTestMessage = strings.TrimSpace(lastTestMessage.String)
	}
	return &item, nil
}

func (s *PostgresStore) decodeConnectorForRead(item *ConnectorConfig) error {
	if item == nil {
		return nil
	}
	if s.connectorCodec == nil {
		if configHasEncryptedSecretPayload(item.ConfigJSON) {
			return fmt.Errorf("encrypted connector secrets detected for %s but %s is not configured", item.ConnectorType, connectorSecretEnvKey)
		}
		return nil
	}
	decoded, err := s.connectorCodec.decryptConfigJSON(item.ConfigJSON)
	if err != nil {
		return fmt.Errorf("decrypt connector config %s: %w", item.ConnectorType, err)
	}
	item.ConfigJSON = decoded
	return nil
}

func (s *PostgresStore) encodeConnectorForWrite(normalizedConfig json.RawMessage, existing *ConnectorConfig) (json.RawMessage, error) {
	if s.connectorCodec == nil {
		if configHasSecretMaterial(normalizedConfig) {
			return nil, fmt.Errorf("refusing to store connector secrets without %s", connectorSecretEnvKey)
		}
		return normalizedConfig, nil
	}
	incoming, err := unmarshalConfigObject(normalizedConfig)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		existingCfg, parseErr := unmarshalConfigObject(existing.ConfigJSON)
		if parseErr != nil {
			return nil, parseErr
		}
		mergeEmptySecretValuesWithExisting(incoming, existingCfg)
	}
	merged, err := json.Marshal(incoming)
	if err != nil {
		return nil, err
	}
	return s.connectorCodec.encryptConfigJSON(json.RawMessage(merged))
}

func normalizeConnectorScope(scopeType ConnectorScopeType, scopeID *uuid.UUID) (ConnectorScopeType, *uuid.UUID, error) {
	switch scopeType {
	case ConnectorScopeGlobal:
		if scopeID != nil {
			return "", nil, ErrInvalidPayload
		}
	case ConnectorScopeProject:
		if scopeID == nil || *scopeID == uuid.Nil {
			return "", nil, ErrInvalidPayload
		}
	default:
		return "", nil, ErrInvalidPayload
	}
	return scopeType, scopeID, nil
}

func (s *PostgresStore) listConnectorConfigsByScope(scopeType ConnectorScopeType, scopeID *uuid.UUID) ([]ConnectorConfig, error) {
	if _, _, err := normalizeConnectorScope(scopeType, scopeID); err != nil {
		return nil, err
	}
	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, connector_type, scope_type, scope_id, config_json, is_enabled,
		        last_test_status, last_test_at, last_test_message, created_at, updated_at
		   FROM connector_configs
		  WHERE scope_type = $1`
	args := []any{string(scopeType)}
	if scopeType == ConnectorScopeGlobal {
		query += " AND scope_id IS NULL"
	} else {
		query += " AND scope_id = $2"
		args = append(args, *scopeID)
	}
	query += " ORDER BY connector_type ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ConnectorConfig, 0, 8)
	for rows.Next() {
		var item ConnectorConfig
		var scannedScopeID uuid.NullUUID
		var lastTestAt sql.NullTime
		var lastTestMessage sql.NullString
		if err := rows.Scan(
			&item.ID,
			&item.ConnectorType,
			&item.ScopeType,
			&scannedScopeID,
			&item.ConfigJSON,
			&item.IsEnabled,
			&item.LastTestStatus,
			&lastTestAt,
			&lastTestMessage,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if scannedScopeID.Valid {
			id := scannedScopeID.UUID
			item.ScopeID = &id
		}
		item.LastTestAt = nullTimePtr(lastTestAt)
		if lastTestMessage.Valid {
			item.LastTestMessage = strings.TrimSpace(lastTestMessage.String)
		}
		if err := s.decodeConnectorForRead(&item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) getConnectorConfigByScope(connectorType ConnectorType, scopeType ConnectorScopeType, scopeID *uuid.UUID) (*ConnectorConfig, error) {
	if !ValidConnectorType(connectorType) {
		return nil, ErrInvalidPayload
	}
	if _, _, err := normalizeConnectorScope(scopeType, scopeID); err != nil {
		return nil, err
	}
	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, connector_type, scope_type, scope_id, config_json, is_enabled,
		        last_test_status, last_test_at, last_test_message, created_at, updated_at
		   FROM connector_configs
		  WHERE connector_type = $1 AND scope_type = $2`
	args := []any{string(connectorType), string(scopeType)}
	if scopeType == ConnectorScopeGlobal {
		query += " AND scope_id IS NULL"
	} else {
		query += " AND scope_id = $3"
		args = append(args, *scopeID)
	}
	query += " LIMIT 1"

	row := s.db.QueryRowContext(ctx, query, args...)
	item, err := scanConnectorConfigRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.decodeConnectorForRead(item); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) upsertConnectorConfigByScope(connectorType ConnectorType, scopeType ConnectorScopeType, scopeID *uuid.UUID, configJSON json.RawMessage, isEnabled bool) (*ConnectorConfig, error) {
	if !ValidConnectorType(connectorType) {
		return nil, ErrInvalidPayload
	}
	if _, _, err := normalizeConnectorScope(scopeType, scopeID); err != nil {
		return nil, err
	}
	normalizedConfig, err := normalizeConnectorConfigJSON(configJSON)
	if err != nil {
		return nil, err
	}
	existing, err := s.getConnectorConfigByScope(connectorType, scopeType, scopeID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		existing = nil
	}
	encodedConfig, err := s.encodeConnectorForWrite(normalizedConfig, existing)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	query := `UPDATE connector_configs
		    SET config_json = $2,
		        is_enabled = $3,
		        updated_at = NOW()
		  WHERE connector_type = $1
		    AND scope_type = $4`
	args := []any{string(connectorType), encodedConfig, isEnabled, string(scopeType)}
	if scopeType == ConnectorScopeGlobal {
		query += " AND scope_id IS NULL"
	} else {
		query += " AND scope_id = $5"
		args = append(args, *scopeID)
	}
	query += `
		RETURNING id, connector_type, scope_type, scope_id, config_json, is_enabled,
		          last_test_status, last_test_at, last_test_message, created_at, updated_at`
	row := tx.QueryRowContext(ctx, query, args...)
	item, err := scanConnectorConfigRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		insertQuery := `INSERT INTO connector_configs (connector_type, scope_type, scope_id, config_json, is_enabled)
			 VALUES ($1, $2, $3, $4, $5)
		RETURNING id, connector_type, scope_type, scope_id, config_json, is_enabled,
		          last_test_status, last_test_at, last_test_message, created_at, updated_at`
		var insertScopeID any = nil
		if scopeType == ConnectorScopeProject {
			insertScopeID = *scopeID
		}
		row = tx.QueryRowContext(ctx, insertQuery, string(connectorType), string(scopeType), insertScopeID, encodedConfig, isEnabled)
		item, err = scanConnectorConfigRow(row)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if err := s.decodeConnectorForRead(item); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PostgresStore) updateConnectorTestStatusByScope(connectorType ConnectorType, scopeType ConnectorScopeType, scopeID *uuid.UUID, status ConnectorTestStatus, message string, testedAt time.Time) (*ConnectorConfig, error) {
	if !ValidConnectorType(connectorType) || !ValidConnectorTestStatus(status) {
		return nil, ErrInvalidPayload
	}
	if _, _, err := normalizeConnectorScope(scopeType, scopeID); err != nil {
		return nil, err
	}
	message = strings.TrimSpace(message)
	if message == "" {
		message = "No details."
	}

	ctx, cancel := s.ctx()
	defer cancel()
	query := `UPDATE connector_configs
		    SET last_test_status = $2,
		        last_test_at = $3,
		        last_test_message = $4,
		        updated_at = NOW()
		  WHERE connector_type = $1
		    AND scope_type = $5`
	args := []any{string(connectorType), string(status), testedAt.UTC(), message, string(scopeType)}
	if scopeType == ConnectorScopeGlobal {
		query += " AND scope_id IS NULL"
	} else {
		query += " AND scope_id = $6"
		args = append(args, *scopeID)
	}
	query += `
		RETURNING id, connector_type, scope_type, scope_id, config_json, is_enabled,
		          last_test_status, last_test_at, last_test_message, created_at, updated_at`

	row := s.db.QueryRowContext(ctx, query, args...)
	item, err := scanConnectorConfigRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := s.decodeConnectorForRead(item); err != nil {
		return nil, err
	}
	return item, nil
}

// ListGlobalConnectorConfigs returns all GLOBAL connector configs.
func (s *PostgresStore) ListGlobalConnectorConfigs() ([]ConnectorConfig, error) {
	return s.listConnectorConfigsByScope(ConnectorScopeGlobal, nil)
}

// GetGlobalConnectorConfig returns a GLOBAL connector config by type.
func (s *PostgresStore) GetGlobalConnectorConfig(connectorType ConnectorType) (*ConnectorConfig, error) {
	return s.getConnectorConfigByScope(connectorType, ConnectorScopeGlobal, nil)
}

// UpsertGlobalConnectorConfig creates or updates GLOBAL connector config.
func (s *PostgresStore) UpsertGlobalConnectorConfig(connectorType ConnectorType, configJSON json.RawMessage, isEnabled bool) (*ConnectorConfig, error) {
	return s.upsertConnectorConfigByScope(connectorType, ConnectorScopeGlobal, nil, configJSON, isEnabled)
}

// UpdateGlobalConnectorTestStatus stores the latest connector config test result.
func (s *PostgresStore) UpdateGlobalConnectorTestStatus(connectorType ConnectorType, status ConnectorTestStatus, message string, testedAt time.Time) (*ConnectorConfig, error) {
	return s.updateConnectorTestStatusByScope(connectorType, ConnectorScopeGlobal, nil, status, message, testedAt)
}

// ListProjectConnectorConfigs returns all PROJECT connector configs for a project.
func (s *PostgresStore) ListProjectConnectorConfigs(projectID uuid.UUID) ([]ConnectorConfig, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	return s.listConnectorConfigsByScope(ConnectorScopeProject, &projectID)
}

// GetProjectConnectorConfig returns a PROJECT connector config by type.
func (s *PostgresStore) GetProjectConnectorConfig(projectID uuid.UUID, connectorType ConnectorType) (*ConnectorConfig, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	return s.getConnectorConfigByScope(connectorType, ConnectorScopeProject, &projectID)
}

// UpsertProjectConnectorConfig creates or updates PROJECT connector config.
func (s *PostgresStore) UpsertProjectConnectorConfig(projectID uuid.UUID, connectorType ConnectorType, configJSON json.RawMessage, isEnabled bool) (*ConnectorConfig, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	return s.upsertConnectorConfigByScope(connectorType, ConnectorScopeProject, &projectID, configJSON, isEnabled)
}

// UpdateProjectConnectorTestStatus stores the latest PROJECT connector test result.
func (s *PostgresStore) UpdateProjectConnectorTestStatus(projectID uuid.UUID, connectorType ConnectorType, status ConnectorTestStatus, message string, testedAt time.Time) (*ConnectorConfig, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	return s.updateConnectorTestStatusByScope(connectorType, ConnectorScopeProject, &projectID, status, message, testedAt)
}
