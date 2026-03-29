package store

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type encryptedConfigArg struct{}

func (encryptedConfigArg) Match(v driver.Value) bool {
	var payload string
	switch typed := v.(type) {
	case []byte:
		payload = string(typed)
	case string:
		payload = typed
	default:
		return false
	}
	return strings.Contains(payload, connectorSecretPrefixV1) && !strings.Contains(payload, "xoxb-plaintext")
}

func testConnectorCodec(t *testing.T) *connectorSecretCodec {
	t.Helper()
	t.Setenv(connectorSecretEnvKey, "base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	codec, err := newConnectorSecretCodecFromEnv()
	if err != nil {
		t.Fatalf("new codec: %v", err)
	}
	if codec == nil {
		t.Fatalf("expected codec")
	}
	return codec
}

func TestMigrateConnectorSecretsAtRestSkipsMissingTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(normalizeQuery(`SELECT id, config_json FROM connector_configs`)).
		WillReturnError(&pgconn.PgError{Code: "42P01"})

	if err := migrateConnectorSecretsAtRest(context.Background(), db, testConnectorCodec(t)); err != nil {
		t.Fatalf("expected missing-table migration to be skipped, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestMigrateConnectorSecretsAtRestEncryptsOnlyUnencryptedRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	needsMigrationID := uuid.New()
	alreadyEncryptedID := uuid.New()

	rows := sqlmock.NewRows([]string{"id", "config_json"}).
		AddRow(needsMigrationID, json.RawMessage(`{"botToken":"xoxb-plaintext","defaultChannel":"#alerts"}`)).
		AddRow(alreadyEncryptedID, json.RawMessage(`{"botToken":"enc:v1:abcdef"}`))

	mock.ExpectQuery(normalizeQuery(`SELECT id, config_json FROM connector_configs`)).
		WillReturnRows(rows)
	mock.ExpectExec(normalizeQuery(`UPDATE connector_configs SET config_json = $2, updated_at = NOW() WHERE id = $1`)).
		WithArgs(needsMigrationID, encryptedConfigArg{}).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := migrateConnectorSecretsAtRest(context.Background(), db, testConnectorCodec(t)); err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
