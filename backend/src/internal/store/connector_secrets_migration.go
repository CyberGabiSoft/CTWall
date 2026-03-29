package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func migrateConnectorSecretsAtRest(ctx context.Context, db *sql.DB, codec *connectorSecretCodec) error {
	if db == nil || codec == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, config_json FROM connector_configs`)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			return nil
		}
		if strings.Contains(strings.ToLower(err.Error()), "connector_configs") && strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return nil
		}
		return err
	}
	defer rows.Close()

	type rowItem struct {
		id     uuid.UUID
		config json.RawMessage
	}
	var toUpdate []rowItem
	for rows.Next() {
		var id uuid.UUID
		var config json.RawMessage
		if err := rows.Scan(&id, &config); err != nil {
			return err
		}
		if !configHasUnencryptedSecretPayload(config) {
			continue
		}
		encrypted, err := codec.encryptConfigJSON(config)
		if err != nil {
			return fmt.Errorf("encrypt connector config %s: %w", id, err)
		}
		toUpdate = append(toUpdate, rowItem{id: id, config: encrypted})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range toUpdate {
		if _, err := db.ExecContext(ctx, `UPDATE connector_configs SET config_json = $2, updated_at = NOW() WHERE id = $1`, item.id, item.config); err != nil {
			return err
		}
	}
	return nil
}
