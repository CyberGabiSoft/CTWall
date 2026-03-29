package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

const storeTimeout = 5 * time.Second

type fileWriter interface {
	Write([]byte) (int, error)
	Close() error
}

var openFile = func(path string, flag int, perm os.FileMode) (fileWriter, error) {
	return os.OpenFile(path, flag, perm)
}

var marshalJSON = json.Marshal

// PostgresStore provides a PostgreSQL-backed store implementation.
type PostgresStore struct {
	db             *sql.DB
	storageRoot    string
	connectorCodec *connectorSecretCodec
}

// NewPostgresStore initializes a PostgreSQL-backed store.
func NewPostgresStore(db *sql.DB, storageRoot string) (*PostgresStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	storageRoot = strings.TrimSpace(storageRoot)
	if storageRoot == "" {
		return nil, ErrInvalidPayload
	}
	if err := os.MkdirAll(storageRoot, 0o755); err != nil {
		return nil, fmt.Errorf("ensure storage root: %w", err)
	}

	connectorCodec, err := newConnectorSecretCodecFromEnv()
	if err != nil {
		return nil, err
	}
	if connectorCodec != nil {
		if err := withStoreTimeout(func(ctx context.Context) error {
			return migrateConnectorSecretsAtRest(ctx, db, connectorCodec)
		}); err != nil {
			return nil, fmt.Errorf("migrate connector secrets at rest: %w", err)
		}
	}

	return &PostgresStore{db: db, storageRoot: storageRoot, connectorCodec: connectorCodec}, nil
}

// Close closes the underlying database connection.
func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), storeTimeout)
}

func withStoreTimeout(run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	return run(ctx)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func scanProduct(row *sql.Row) (*models.Product, error) {
	var product models.Product
	if err := row.Scan(&product.ID, &product.ProjectID, &product.Name, &product.Description, &product.ArchivedAt, &product.CreatedAt, &product.UpdatedAt); err != nil {
		return nil, err
	}
	return &product, nil
}

func scanScope(row *sql.Row) (*models.Scope, error) {
	var scope models.Scope
	if err := row.Scan(&scope.ID, &scope.ProductID, &scope.Name, &scope.Description, &scope.ArchivedAt, &scope.CreatedAt, &scope.UpdatedAt); err != nil {
		return nil, err
	}
	return &scope, nil
}

func scanTest(row *sql.Row) (*models.Test, error) {
	var test models.Test
	var publicToken sql.NullString
	if err := row.Scan(&test.ID, &test.ScopeID, &test.Name, &test.SbomStandard, &test.SbomSpecVersion, &test.IsPublic, &publicToken, &test.ArchivedAt, &test.CreatedAt, &test.UpdatedAt); err != nil {
		return nil, err
	}
	if publicToken.Valid {
		test.PublicToken = publicToken.String
	}
	return &test, nil
}

func scanAuditLogRow(rows *sql.Rows) (*models.AuditLog, error) {
	var entry models.AuditLog
	var actorID uuid.NullUUID
	var entityID uuid.NullUUID
	var ipAddress sql.NullString
	if err := rows.Scan(
		&entry.ID,
		&actorID,
		&entry.Action,
		&entry.EntityType,
		&entityID,
		&entry.Details,
		&ipAddress,
		&entry.CreatedAt,
	); err != nil {
		return nil, err
	}
	entry.Action = strings.TrimSpace(entry.Action)
	entry.EntityType = strings.TrimSpace(entry.EntityType)
	if actorID.Valid {
		id := actorID.UUID
		entry.ActorID = &id
	}
	if entityID.Valid {
		id := entityID.UUID
		entry.EntityID = &id
	}
	if ipAddress.Valid {
		entry.IPAddress = strings.TrimSpace(ipAddress.String)
	}
	return &entry, nil
}

func scanRevision(row *sql.Row) (*models.TestRevision, error) {
	var revision models.TestRevision
	var tagsRaw []byte
	var metadataRaw []byte
	var sbomMetadataRaw []byte
	if err := row.Scan(
		&revision.ID,
		&revision.TestID,
		&revision.SbomSha256,
		&revision.SbomProducer,
		&tagsRaw,
		&metadataRaw,
		&sbomMetadataRaw,
		&revision.ComponentsImportedCount,
		&revision.IsActive,
		&revision.LastModifiedAt,
		&revision.CreatedAt,
	); err != nil {
		return nil, err
	}
	if len(tagsRaw) > 0 {
		if err := json.Unmarshal(tagsRaw, &revision.Tags); err != nil {
			return nil, err
		}
	}
	if len(metadataRaw) > 0 {
		revision.MetadataJSON = json.RawMessage(metadataRaw)
	}
	if len(sbomMetadataRaw) > 0 {
		revision.SbomMetadataJSON = json.RawMessage(sbomMetadataRaw)
	}
	return &revision, nil
}

func scanUser(row *sql.Row) (*models.User, error) {
	var user models.User
	var fullName sql.NullString
	if err := row.Scan(&user.ID, &user.Email, &user.Role, &user.AccountType, &user.Nickname, &fullName, &user.CreatedAt, &user.UpdatedAt); err != nil {
		return nil, err
	}
	user.FullName = nullStringToString(fullName)
	return &user, nil
}

func scanUserCredentials(row *sql.Row) (*UserCredentials, error) {
	var creds UserCredentials
	var fullName sql.NullString
	if err := row.Scan(
		&creds.User.ID,
		&creds.User.Email,
		&creds.User.Role,
		&creds.User.AccountType,
		&creds.User.Nickname,
		&fullName,
		&creds.User.CreatedAt,
		&creds.User.UpdatedAt,
		&creds.PasswordHash,
	); err != nil {
		return nil, err
	}
	creds.User.FullName = nullStringToString(fullName)
	return &creds, nil
}

func scanAPITokenWithUser(row *sql.Row) (*APIToken, *models.User, error) {
	var token APIToken
	var user models.User
	var lastUsed sql.NullTime
	var expires sql.NullTime
	var fullName sql.NullString
	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&lastUsed,
		&expires,
		&token.CreatedAt,
		&user.ID,
		&user.Email,
		&user.Role,
		&user.AccountType,
		&user.Nickname,
		&fullName,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		return nil, nil, err
	}
	token.LastUsedAt = nullTimePtr(lastUsed)
	token.ExpiresAt = nullTimePtr(expires)
	user.FullName = nullStringToString(fullName)
	return &token, &user, nil
}

func scanAPIToken(row *sql.Row) (*APIToken, error) {
	var token APIToken
	var lastUsed sql.NullTime
	var expires sql.NullTime
	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.Name,
		&token.TokenHash,
		&lastUsed,
		&expires,
		&token.CreatedAt,
	); err != nil {
		return nil, err
	}
	token.LastUsedAt = nullTimePtr(lastUsed)
	token.ExpiresAt = nullTimePtr(expires)
	return &token, nil
}

func scanRefreshToken(row *sql.Row) (*RefreshToken, error) {
	var token RefreshToken
	var revoked sql.NullTime
	var replaced sql.NullString
	var lastUsed sql.NullTime
	if err := row.Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&revoked,
		&replaced,
		&token.CreatedAt,
		&lastUsed,
		&token.UserAgent,
		&token.IPAddress,
	); err != nil {
		return nil, err
	}
	token.RevokedAt = nullTimePtr(revoked)
	if replaced.Valid {
		if id, err := uuid.Parse(replaced.String); err == nil {
			token.ReplacedByID = &id
		}
	}
	token.LastUsedAt = nullTimePtr(lastUsed)
	return &token, nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if value.Valid {
		return &value.Time
	}
	return nil
}

func nullStringToString(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

// GetUserByEmail returns a user with password hash by email.
func (s *PostgresStore) CreateAuditLog(entry AuditLogEntry) error {
	ctx, cancel := s.ctx()
	defer cancel()

	var details json.RawMessage
	if len(entry.Details) > 0 {
		normalized, changed, err := eventmeta.NormalizeCategoryToSystem(entry.Details)
		if err != nil {
			return ErrInvalidPayload
		}
		if changed {
			// Do not drop audit records due to an invalid category (normalize to system).
			slog.Error("audit log details had invalid category; normalized to system", "component", "store.audit_logs")
		}
		if err := eventmeta.ValidateDetails(normalized); err != nil {
			return ErrInvalidPayload
		}
		details = normalized
	}
	if len(details) == 0 {
		return ErrInvalidPayload
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, details, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.ActorID,
		entry.Action,
		entry.EntityType,
		entry.EntityID,
		details,
		strings.TrimSpace(entry.IPAddress),
	)
	return err
}

// ListAuditLogs returns audit logs filtered by entity and action prefix.
func (s *PostgresStore) ListAuditLogs(entityType string, entityID *uuid.UUID, actionPrefix string, limit, offset int) ([]models.AuditLog, error) {
	entityType = strings.TrimSpace(entityType)
	if entityType == "" {
		return nil, ErrInvalidPayload
	}
	if limit <= 0 || offset < 0 {
		return nil, ErrInvalidPayload
	}
	actionPrefix = strings.TrimSpace(actionPrefix)

	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, actor_id, action, entity_type, entity_id, details, ip_address, created_at
		FROM audit_logs
		WHERE entity_type = $1`
	args := []any{entityType}

	if entityID != nil {
		query += fmt.Sprintf(" AND entity_id = $%d", len(args)+1)
		args = append(args, *entityID)
	}
	if actionPrefix != "" {
		pattern := actionPrefix
		if !strings.HasSuffix(pattern, "%") {
			pattern += "%"
		}
		query += fmt.Sprintf(" AND action LIKE $%d", len(args)+1)
		args = append(args, pattern)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]models.AuditLog, 0)
	for rows.Next() {
		entry, err := scanAuditLogRow(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ListAuditLogsExcludingAction returns audit logs filtered by entity and action prefix, excluding a single action.
func (s *PostgresStore) ListAuditLogsExcludingAction(entityType string, entityID *uuid.UUID, actionPrefix string, excludedAction string, limit, offset int) ([]models.AuditLog, error) {
	entityType = strings.TrimSpace(entityType)
	if entityType == "" {
		return nil, ErrInvalidPayload
	}
	if limit <= 0 || offset < 0 {
		return nil, ErrInvalidPayload
	}
	actionPrefix = strings.TrimSpace(actionPrefix)
	excludedAction = strings.TrimSpace(excludedAction)

	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, actor_id, action, entity_type, entity_id, details, ip_address, created_at
		FROM audit_logs
		WHERE entity_type = $1`
	args := []any{entityType}

	if entityID != nil {
		query += fmt.Sprintf(" AND entity_id = $%d", len(args)+1)
		args = append(args, *entityID)
	}
	if actionPrefix != "" {
		pattern := actionPrefix
		if !strings.HasSuffix(pattern, "%") {
			pattern += "%"
		}
		query += fmt.Sprintf(" AND action LIKE $%d", len(args)+1)
		args = append(args, pattern)
	}
	if excludedAction != "" {
		query += fmt.Sprintf(" AND action <> $%d", len(args)+1)
		args = append(args, excludedAction)
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]models.AuditLog, 0)
	for rows.Next() {
		entry, err := scanAuditLogRow(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ListAuditLogsByActionAndDetail returns audit logs filtered by entity and an exact action, additionally matching details->>key = value.
func (s *PostgresStore) ListAuditLogsByActionAndDetail(entityType string, entityID *uuid.UUID, action string, detailsKey string, detailsValue string, limit, offset int) ([]models.AuditLog, error) {
	entityType = strings.TrimSpace(entityType)
	action = strings.TrimSpace(action)
	detailsKey = strings.TrimSpace(detailsKey)
	detailsValue = strings.TrimSpace(detailsValue)
	if entityType == "" || action == "" || detailsKey == "" || detailsValue == "" {
		return nil, ErrInvalidPayload
	}
	if limit <= 0 || offset < 0 {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	query := `SELECT id, actor_id, action, entity_type, entity_id, details, ip_address, created_at
		FROM audit_logs
		WHERE entity_type = $1 AND action = $2`
	args := []any{entityType, action}

	if entityID != nil {
		query += fmt.Sprintf(" AND entity_id = $%d", len(args)+1)
		args = append(args, *entityID)
	}
	// jsonb ->> operator accepts a text key; passing it as a parameter avoids SQL injection.
	query += fmt.Sprintf(" AND details ->> $%d = $%d", len(args)+1, len(args)+2)
	args = append(args, detailsKey, detailsValue)

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]models.AuditLog, 0)
	for rows.Next() {
		entry, err := scanAuditLogRow(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *PostgresStore) EnsureProduct(name, description string) (*models.Product, bool, error) {
	if strings.TrimSpace(name) == "" {
		return nil, false, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	defaultProjectID, err := s.defaultProjectID(ctx)
	if err != nil {
		return nil, false, err
	}
	return s.EnsureProductInProject(defaultProjectID, name, description)
}

func (s *PostgresStore) CreateProduct(name, description string) (*models.Product, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()
	defaultProjectID, err := s.defaultProjectID(ctx)
	if err != nil {
		return nil, err
	}
	return s.CreateProductInProject(defaultProjectID, name, description)
}

func (s *PostgresStore) GetProduct(id uuid.UUID) (*models.Product, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE id = $1`, id)
	product, err := scanProduct(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return product, nil
}

func (s *PostgresStore) ListProducts() ([]models.Product, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE archived_at IS NULL
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	products := make([]models.Product, 0)
	for rows.Next() {
		var product models.Product
		if err := rows.Scan(&product.ID, &product.ProjectID, &product.Name, &product.Description, &product.ArchivedAt, &product.CreatedAt, &product.UpdatedAt); err != nil {
			return nil, err
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return products, nil
}

func (s *PostgresStore) DeleteProduct(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	shas, err := collectSbomSHAs(ctx, s.db,
		`SELECT DISTINCT tr.sbom_sha256
		 FROM test_revisions tr
		 JOIN tests t ON tr.test_id = t.id
		 JOIN scopes s ON t.scope_id = s.id
		 WHERE s.product_id = $1`, id)
	if err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM products WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	if err := s.cleanupSbomObjects(ctx, shas); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) EnsureScope(productID uuid.UUID, name, description string) (*models.Scope, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, false, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProductExists(ctx, productID); err != nil {
		return nil, false, err
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE product_id = $1 AND LOWER(name) = LOWER($2)
		 LIMIT 1`, productID, name)
	scope, err := scanScope(row)
	if err == nil {
		return scope, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	created, err := s.CreateScope(productID, name, description)
	if err == ErrAlreadyExists {
		row = s.db.QueryRowContext(ctx,
			`SELECT id, product_id, name, description, archived_at, created_at, updated_at
			 FROM scopes
			 WHERE product_id = $1 AND LOWER(name) = LOWER($2)
			 LIMIT 1`, productID, name)
		scope, err = scanScope(row)
		if err != nil {
			return nil, false, err
		}
		return scope, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func (s *PostgresStore) CreateScope(productID uuid.UUID, name, description string) (*models.Scope, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO scopes (product_id, name, description)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (product_id, LOWER(name)) DO NOTHING
		 RETURNING id, product_id, name, description, archived_at, created_at, updated_at`,
		productID,
		name,
		strings.TrimSpace(description),
	)
	scope, err := scanScope(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return scope, nil
}

func (s *PostgresStore) GetScope(id uuid.UUID) (*models.Scope, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE id = $1`, id)
	scope, err := scanScope(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return scope, nil
}

func (s *PostgresStore) ListScopes(productID uuid.UUID) ([]models.Scope, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProductExists(ctx, productID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE product_id = $1 AND archived_at IS NULL
		 ORDER BY name`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scopes := make([]models.Scope, 0)
	for rows.Next() {
		var scope models.Scope
		if err := rows.Scan(&scope.ID, &scope.ProductID, &scope.Name, &scope.Description, &scope.ArchivedAt, &scope.CreatedAt, &scope.UpdatedAt); err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (s *PostgresStore) DeleteScope(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	shas, err := collectSbomSHAs(ctx, s.db,
		`SELECT DISTINCT tr.sbom_sha256
		 FROM test_revisions tr
		 JOIN tests t ON tr.test_id = t.id
		 WHERE t.scope_id = $1`, id)
	if err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM scopes WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	if err := s.cleanupSbomObjects(ctx, shas); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) EnsureTest(scopeID uuid.UUID, name, sbomStandard, sbomSpecVersion string) (*models.Test, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, false, ErrInvalidPayload
	}
	sbomStandard = strings.TrimSpace(sbomStandard)
	sbomSpecVersion = strings.TrimSpace(sbomSpecVersion)
	if sbomStandard == "" {
		return nil, false, ErrInvalidPayload
	}
	if sbomSpecVersion == "" {
		sbomSpecVersion = "unknown"
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureScopeExists(ctx, scopeID); err != nil {
		return nil, false, err
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE scope_id = $1 AND LOWER(name) = LOWER($2)
		   AND sbom_standard = $3 AND sbom_spec_version = $4
		 LIMIT 1`, scopeID, name, sbomStandard, sbomSpecVersion)
	test, err := scanTest(row)
	if err == nil {
		return test, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	created, err := s.createTest(scopeID, name, sbomStandard, sbomSpecVersion)
	if err == ErrAlreadyExists {
		row = s.db.QueryRowContext(ctx,
			`SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
			 FROM tests
			 WHERE scope_id = $1 AND LOWER(name) = LOWER($2)
			   AND sbom_standard = $3 AND sbom_spec_version = $4
			 LIMIT 1`, scopeID, name, sbomStandard, sbomSpecVersion)
		test, err = scanTest(row)
		if err != nil {
			return nil, false, err
		}
		return test, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func (s *PostgresStore) GetTest(id uuid.UUID) (*models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE id = $1`, id)
	test, err := scanTest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return test, nil
}

func (s *PostgresStore) ListTests(scopeID uuid.UUID) ([]models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureScopeExists(ctx, scopeID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE scope_id = $1 AND archived_at IS NULL
		 ORDER BY name`, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tests := make([]models.Test, 0)
	for rows.Next() {
		var test models.Test
		var publicToken sql.NullString
		if err := rows.Scan(&test.ID, &test.ScopeID, &test.Name, &test.SbomStandard, &test.SbomSpecVersion, &test.IsPublic, &publicToken, &test.ArchivedAt, &test.CreatedAt, &test.UpdatedAt); err != nil {
			return nil, err
		}
		if publicToken.Valid {
			test.PublicToken = publicToken.String
		}
		tests = append(tests, test)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tests, nil
}

func (s *PostgresStore) DeleteTest(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	shas, err := collectSbomSHAs(ctx, s.db,
		`SELECT DISTINCT sbom_sha256 FROM test_revisions WHERE test_id = $1`, id)
	if err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM tests WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	if err := s.cleanupSbomObjects(ctx, shas); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) AddRevision(testID uuid.UUID, input RevisionInput) (*models.TestRevision, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := ensureTestExistsTx(ctx, tx, testID); err != nil {
		return nil, err
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`, testID)
	if err != nil {
		return nil, err
	}

	tagsJSON, err := marshalJSON(input.Tags)
	if err != nil {
		return nil, ErrInvalidPayload
	}
	componentsCount := input.ComponentsImportedCount
	if len(input.Components) > 0 {
		componentsCount = len(input.Components)
	}
	sbomProducer := strings.TrimSpace(input.SbomProducer)
	if sbomProducer == "" {
		sbomProducer = "other"
	}

	row := tx.QueryRowContext(ctx,
		`INSERT INTO test_revisions (test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NOW())
		 RETURNING id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at`,
		testID,
		input.SbomSha256,
		sbomProducer,
		tagsJSON,
		input.MetadataJSON,
		input.SbomMetadataJSON,
		componentsCount,
	)
	revision, err := scanRevision(row)
	if err != nil {
		return nil, err
	}

	if len(input.Components) > 0 {
		if err := insertComponentsTx(ctx, tx, revision.ID, input.Components); err != nil {
			return nil, err
		}
	}

	// Ensure malware summary row exists for the new revision and enqueue recomputation.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO test_revision_malware_summary (revision_id)
		 VALUES ($1)
		 ON CONFLICT (revision_id) DO NOTHING`, revision.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO test_revision_malware_summary_queue (revision_id, status, reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (revision_id) DO UPDATE SET
		     status = EXCLUDED.status,
		     reason = EXCLUDED.reason,
		     updated_at = NOW(),
		     completed_at = NULL,
		     last_error = NULL`,
		revision.ID,
		TestRevisionMalwareSummaryStatusPending,
		TestRevisionMalwareSummaryReasonIngest,
	); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE tests SET updated_at = NOW() WHERE id = $1`, testID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if _, diffErr := s.EnqueueTestRevisionFindingDiff(revision.ID, TestRevisionFindingDiffReasonIngest); diffErr != nil {
		slog.Error(
			"failed to enqueue revision finding diff job",
			"component", "store.revision_diff.enqueue",
			"revision_id", revision.ID,
			"error", diffErr,
		)
	}
	return revision, nil
}

func insertComponentsTx(ctx context.Context, tx *sql.Tx, revisionID uuid.UUID, components []ComponentInput) error {
	if len(components) == 0 {
		return nil
	}

	const batchSize = 500
	for start := 0; start < len(components); start += batchSize {
		end := start + batchSize
		if end > len(components) {
			end = len(components)
		}
		batch := components[start:end]

		var builder strings.Builder
		builder.WriteString(`INSERT INTO components (revision_id, purl, pkg_name, version, pkg_type, pkg_namespace, sbom_type, publisher, supplier, licenses, properties) VALUES `)

		args := make([]any, 0, len(batch)*11)
		argIndex := 1
		for i, component := range batch {
			purl := strings.TrimSpace(component.PURL)
			pkgName := strings.TrimSpace(component.PkgName)
			version := strings.TrimSpace(component.Version)
			pkgType := strings.TrimSpace(component.PkgType)
			pkgNamespace := strings.TrimSpace(component.PkgNamespace)
			sbomType := strings.TrimSpace(component.SbomType)
			publisher := strings.TrimSpace(component.Publisher)
			supplier := strings.TrimSpace(component.Supplier)

			if purl == "" || pkgName == "" {
				return ErrInvalidPayload
			}
			if version == "" {
				version = "unknown"
			}
			if pkgType == "" {
				pkgType = "unknown"
			}
			if sbomType == "" {
				sbomType = "unknown"
			}

			if i > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				argIndex, argIndex+1, argIndex+2, argIndex+3, argIndex+4, argIndex+5, argIndex+6, argIndex+7, argIndex+8, argIndex+9, argIndex+10))

			args = append(args,
				revisionID,
				purl,
				pkgName,
				version,
				pkgType,
				nullIfEmpty(pkgNamespace),
				sbomType,
				nullIfEmpty(publisher),
				nullIfEmpty(supplier),
				nonEmptyJSONBytes(component.Licenses, []byte("[]")),
				nonEmptyJSONBytes(component.Properties, []byte("{}")),
			)
			argIndex += 11
		}

		if _, err := tx.ExecContext(ctx, builder.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullIfEmptyBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nonEmptyJSONBytes(value []byte, fallback []byte) []byte {
	if len(value) == 0 {
		return append([]byte(nil), fallback...)
	}
	return value
}

func (s *PostgresStore) ListRevisions(testID uuid.UUID) ([]models.TestRevision, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json,
		        components_count, is_active, last_modified_at, created_at
		 FROM test_revisions
		 WHERE test_id = $1
		 ORDER BY created_at`, testID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	revisions := make([]models.TestRevision, 0)
	for rows.Next() {
		var revision models.TestRevision
		var tagsRaw []byte
		var metadataRaw []byte
		var sbomMetadataRaw []byte
		if err := rows.Scan(
			&revision.ID,
			&revision.TestID,
			&revision.SbomSha256,
			&revision.SbomProducer,
			&tagsRaw,
			&metadataRaw,
			&sbomMetadataRaw,
			&revision.ComponentsImportedCount,
			&revision.IsActive,
			&revision.LastModifiedAt,
			&revision.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(tagsRaw) > 0 {
			if err := json.Unmarshal(tagsRaw, &revision.Tags); err != nil {
				return nil, err
			}
		}
		if len(metadataRaw) > 0 {
			revision.MetadataJSON = json.RawMessage(metadataRaw)
		}
		if len(sbomMetadataRaw) > 0 {
			revision.SbomMetadataJSON = json.RawMessage(sbomMetadataRaw)
		}
		revisions = append(revisions, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return revisions, nil
}

func (s *PostgresStore) GetRevision(id uuid.UUID) (*models.TestRevision, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json,
		        components_count, is_active, last_modified_at, created_at
		 FROM test_revisions
		 WHERE id = $1`, id)
	revision, err := scanRevision(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return revision, nil
}

func (s *PostgresStore) DeleteRevision(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var testID uuid.UUID
	var sbomSHA string
	var wasActive bool
	if err := tx.QueryRowContext(ctx,
		`SELECT test_id, sbom_sha256, is_active
		 FROM test_revisions
		 WHERE id = $1`, id).Scan(&testID, &sbomSHA, &wasActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM test_revisions WHERE id = $1`, id); err != nil {
		return err
	}

	if wasActive {
		var nextID uuid.UUID
		err = tx.QueryRowContext(ctx,
			`SELECT id FROM test_revisions
			 WHERE test_id = $1
			 ORDER BY created_at DESC
			 LIMIT 1`, testID).Scan(&nextID)
		if err == nil {
			if _, err := tx.ExecContext(ctx,
				`UPDATE test_revisions
				 SET is_active = TRUE, last_modified_at = NOW()
				 WHERE id = $1`, nextID); err != nil {
				return err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	var remaining int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(1) FROM test_revisions WHERE sbom_sha256 = $1`, sbomSHA).Scan(&remaining); err != nil {
		return err
	}

	var storagePath string
	if remaining == 0 {
		if err := tx.QueryRowContext(ctx,
			`SELECT storage_path FROM sbom_objects WHERE sha256 = $1`, sbomSHA).Scan(&storagePath); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sbom_objects WHERE sha256 = $1`, sbomSHA); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	if remaining == 0 && storagePath != "" {
		path := filepath.Join(s.storageRoot, storagePath)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) ListAllRevisions() ([]models.TestRevision, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json,
		        components_count, is_active, last_modified_at, created_at
		 FROM test_revisions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	revisions := make([]models.TestRevision, 0)
	for rows.Next() {
		var revision models.TestRevision
		var tagsRaw []byte
		var metadataRaw []byte
		var sbomMetadataRaw []byte
		if err := rows.Scan(
			&revision.ID,
			&revision.TestID,
			&revision.SbomSha256,
			&revision.SbomProducer,
			&tagsRaw,
			&metadataRaw,
			&sbomMetadataRaw,
			&revision.ComponentsImportedCount,
			&revision.IsActive,
			&revision.LastModifiedAt,
			&revision.CreatedAt,
		); err != nil {
			return nil, err
		}
		if len(tagsRaw) > 0 {
			if err := json.Unmarshal(tagsRaw, &revision.Tags); err != nil {
				return nil, err
			}
		}
		if len(metadataRaw) > 0 {
			revision.MetadataJSON = json.RawMessage(metadataRaw)
		}
		if len(sbomMetadataRaw) > 0 {
			revision.SbomMetadataJSON = json.RawMessage(sbomMetadataRaw)
		}
		revisions = append(revisions, revision)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return revisions, nil
}

func (s *PostgresStore) ListComponents(testID uuid.UUID) ([]models.Component, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT c.id, c.revision_id, c.purl, c.pkg_name, c.version, c.pkg_type, COALESCE(c.pkg_namespace, ''),
		        c.sbom_type, COALESCE(c.publisher, ''), COALESCE(c.supplier, ''), COALESCE(c.licenses, '[]'::jsonb), COALESCE(c.properties, '{}'::jsonb), c.created_at
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 WHERE tr.test_id = $1 AND tr.is_active = TRUE
		 ORDER BY c.pkg_name, c.version`, testID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	components := make([]models.Component, 0)
	for rows.Next() {
		var component models.Component
		if err := rows.Scan(
			&component.ID,
			&component.RevisionID,
			&component.PURL,
			&component.PkgName,
			&component.Version,
			&component.PkgType,
			&component.PkgNamespace,
			&component.SbomType,
			&component.Publisher,
			&component.Supplier,
			&component.Licenses,
			&component.Properties,
			&component.CreatedAt,
		); err != nil {
			return nil, err
		}
		components = append(components, component)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return components, nil
}

func (s *PostgresStore) CountComponents(testID uuid.UUID) (int, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return 0, err
	}

	var count int
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*)
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 WHERE tr.test_id = $1 AND tr.is_active = TRUE`, testID)
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *PostgresStore) ListComponentsPage(
	testID uuid.UUID,
	filter ComponentListFilter,
	sort ComponentListSort,
	limit, offset int,
) ([]models.Component, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return []models.Component{}, nil
	}
	if offset < 0 {
		offset = 0
	}

	var orderBy string
	switch sort.Field {
	case "createdAt":
		orderBy = "c.created_at"
	case "purl":
		orderBy = "c.purl"
	case "version":
		orderBy = "c.version"
	case "pkgType":
		orderBy = "c.pkg_type"
	case "pkgNamespace":
		orderBy = "c.pkg_namespace"
	case "sbomType":
		orderBy = "c.sbom_type"
	case "publisher":
		orderBy = "c.publisher"
	case "supplier":
		orderBy = "c.supplier"
	default:
		orderBy = "c.pkg_name"
	}
	dir := "ASC"
	if sort.Desc {
		dir = "DESC"
	}

	// Build a safe parameterized query. All filter values have already been sanitized.
	var b strings.Builder
	args := make([]any, 0, 16)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	b.WriteString(`SELECT c.id, c.revision_id, c.purl, c.pkg_name, c.version, c.pkg_type, COALESCE(c.pkg_namespace, ''),
		        c.sbom_type, COALESCE(c.publisher, ''), COALESCE(c.supplier, ''), COALESCE(c.licenses, '[]'::jsonb), COALESCE(c.properties, '{}'::jsonb), c.created_at
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 WHERE tr.test_id = `)
	b.WriteString(arg(testID))
	b.WriteString(` AND tr.is_active = TRUE`)

	if filter.PkgName != "" {
		b.WriteString(` AND LOWER(c.pkg_name) = LOWER(`)
		b.WriteString(arg(filter.PkgName))
		b.WriteString(`)`)
	}
	if filter.PURL != "" {
		b.WriteString(` AND c.purl ILIKE '%' || `)
		b.WriteString(arg(filter.PURL))
		b.WriteString(` || '%'`)
	}
	if filter.PkgType != "" {
		b.WriteString(` AND LOWER(c.pkg_type) = LOWER(`)
		b.WriteString(arg(filter.PkgType))
		b.WriteString(`)`)
	}
	if filter.PkgNamespace != "" {
		b.WriteString(` AND LOWER(COALESCE(c.pkg_namespace, '')) = LOWER(`)
		b.WriteString(arg(filter.PkgNamespace))
		b.WriteString(`)`)
	}
	if filter.Version != "" {
		b.WriteString(` AND LOWER(c.version) = LOWER(`)
		b.WriteString(arg(filter.Version))
		b.WriteString(`)`)
	}
	if filter.SbomType != "" {
		b.WriteString(` AND LOWER(COALESCE(c.sbom_type, '')) = LOWER(`)
		b.WriteString(arg(filter.SbomType))
		b.WriteString(`)`)
	}
	if filter.Publisher != "" {
		b.WriteString(` AND LOWER(COALESCE(c.publisher, '')) = LOWER(`)
		b.WriteString(arg(filter.Publisher))
		b.WriteString(`)`)
	}
	if filter.Supplier != "" {
		b.WriteString(` AND LOWER(COALESCE(c.supplier, '')) = LOWER(`)
		b.WriteString(arg(filter.Supplier))
		b.WriteString(`)`)
	}
	if filter.Query != "" {
		qParam := arg(filter.Query)
		b.WriteString(` AND (c.pkg_name ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR c.purl ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR c.version ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR c.pkg_type ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR COALESCE(c.pkg_namespace,'') ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR COALESCE(c.sbom_type,'') ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR COALESCE(c.publisher,'') ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%' OR COALESCE(c.supplier,'') ILIKE '%' || `)
		b.WriteString(qParam)
		b.WriteString(` || '%')`)
	}

	b.WriteString(` ORDER BY `)
	b.WriteString(orderBy)
	b.WriteString(` `)
	b.WriteString(dir)
	b.WriteString(`, c.id ASC`)

	b.WriteString(` LIMIT `)
	b.WriteString(arg(limit))
	b.WriteString(` OFFSET `)
	b.WriteString(arg(offset))

	rows, err := s.db.QueryContext(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	components := make([]models.Component, 0)
	for rows.Next() {
		var component models.Component
		if err := rows.Scan(
			&component.ID,
			&component.RevisionID,
			&component.PURL,
			&component.PkgName,
			&component.Version,
			&component.PkgType,
			&component.PkgNamespace,
			&component.SbomType,
			&component.Publisher,
			&component.Supplier,
			&component.Licenses,
			&component.Properties,
			&component.CreatedAt,
		); err != nil {
			return nil, err
		}
		components = append(components, component)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return components, nil
}

func (s *PostgresStore) GetComponent(testID, componentID uuid.UUID) (*models.Component, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureTestExists(ctx, testID); err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT c.id, c.revision_id, c.purl, c.pkg_name, c.version, c.pkg_type, COALESCE(c.pkg_namespace, ''),
		        c.sbom_type, COALESCE(c.publisher, ''), COALESCE(c.supplier, ''), COALESCE(c.licenses, '[]'::jsonb), COALESCE(c.properties, '{}'::jsonb), c.created_at
		 FROM components c
		 JOIN test_revisions tr ON tr.id = c.revision_id
		 WHERE tr.test_id = $1 AND tr.is_active = TRUE AND c.id = $2`, testID, componentID)
	var component models.Component
	if err := row.Scan(
		&component.ID,
		&component.RevisionID,
		&component.PURL,
		&component.PkgName,
		&component.Version,
		&component.PkgType,
		&component.PkgNamespace,
		&component.SbomType,
		&component.Publisher,
		&component.Supplier,
		&component.Licenses,
		&component.Properties,
		&component.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &component, nil
}

func (s *PostgresStore) CreateIngestJob(input IngestRequest) (*IngestJob, error) {
	if input.ProductID == nil || *input.ProductID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if input.ScopeID == nil || *input.ScopeID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	if input.TestID == nil || *input.TestID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	sbomSHA := strings.TrimSpace(input.SbomSha256)
	if sbomSHA == "" {
		return nil, ErrInvalidPayload
	}
	sbomStandard := strings.ToLower(strings.TrimSpace(input.SbomStandard))
	sbomSpecVersion := strings.ToLower(strings.TrimSpace(input.SbomSpecVersion))
	sbomProducer := strings.ToLower(strings.TrimSpace(input.SbomProducer))
	if sbomStandard == "" {
		return nil, ErrInvalidPayload
	}
	if sbomSpecVersion == "" {
		sbomSpecVersion = "unknown"
	}
	if sbomProducer == "" {
		sbomProducer = "other"
	}
	trimmedTags := make([]string, 0, len(input.Tags))
	for _, tag := range input.Tags {
		if trimmed := strings.TrimSpace(tag); trimmed != "" {
			trimmedTags = append(trimmedTags, trimmed)
		}
	}
	tagsJSON, err := marshalJSON(trimmedTags)
	if err != nil {
		return nil, err
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO ingest_queue (
			 product_id, scope_id, test_id,
			 sbom_sha256, sbom_standard, sbom_spec_version, sbom_producer,
			 tags, metadata_json, content_type, is_gzip, components_count, processing_stage, status
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 RETURNING id, status, processing_stage, error_message, created_at, updated_at, completed_at`,
		input.ProductID,
		input.ScopeID,
		input.TestID,
		sbomSHA,
		sbomStandard,
		sbomSpecVersion,
		sbomProducer,
		tagsJSON,
		input.MetadataJSON,
		strings.TrimSpace(input.ContentType),
		input.IsGzip,
		input.ComponentsCount,
		IngestStageReceived,
		IngestStatusPending,
	)

	var errorMessage sql.NullString
	job := &IngestJob{IngestRequest: input}
	if err := row.Scan(&job.ID, &job.Status, &job.ProcessingStage, &errorMessage, &job.CreatedAt, &job.UpdatedAt, &job.CompletedAt); err != nil {
		return nil, err
	}
	if errorMessage.Valid {
		job.ErrorMessage = errorMessage.String
	}
	job.ProcessingStage = normalizeIngestStage(job.ProcessingStage)
	job.SbomSha256 = sbomSHA
	job.SbomStandard = sbomStandard
	job.SbomSpecVersion = sbomSpecVersion
	job.SbomProducer = sbomProducer
	job.ContentType = strings.TrimSpace(job.ContentType)
	job.Tags = trimmedTags
	return job, nil
}

func (s *PostgresStore) UpdateIngestJobStatus(id uuid.UUID, status string, errorMessage string) error {
	if !isValidIngestStatus(status) {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	normalized := normalizeIngestStatus(status)
	var current string
	if err := s.db.QueryRowContext(ctx, `SELECT status FROM ingest_queue WHERE id = $1`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !ingestState.CanTransition(current, normalized) {
		return ErrInvalidStateTransition
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE ingest_queue
		 SET status = $1,
		     error_message = NULLIF($2, ''),
		     updated_at = NOW(),
		     completed_at = CASE WHEN $1 IN ('COMPLETED', 'FAILED') THEN NOW() ELSE NULL END
		 WHERE id = $3`,
		normalized,
		strings.TrimSpace(errorMessage),
		id,
	)
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

func (s *PostgresStore) UpdateIngestJobStage(id uuid.UUID, stage string, errorMessage string) error {
	if !isValidIngestStage(stage) {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	normalized := normalizeIngestStage(stage)
	var current string
	if err := s.db.QueryRowContext(ctx, `SELECT processing_stage FROM ingest_queue WHERE id = $1`, id).Scan(&current); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !ingestStage.CanTransition(current, normalized) {
		return ErrInvalidStateTransition
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE ingest_queue
		 SET processing_stage = $1, error_message = $2, updated_at = NOW()
		 WHERE id = $3`,
		normalized,
		strings.TrimSpace(errorMessage),
		id,
	)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) StoreSbom(sha string, data []byte, format string, contentType string, isGzip bool) (*SbomObject, error) {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return nil, ErrInvalidPayload
	}

	meta, err := s.loadSbomMeta(sha)
	if err == nil {
		meta.Bytes = data
		return meta, nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	relativePath, err := sbomRelativePath(sha)
	if err != nil {
		return nil, err
	}
	fullPath := filepath.Join(s.storageRoot, relativePath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return nil, fmt.Errorf("create storage dir: %w", err)
	}

	if err := writeFileIfMissing(fullPath, data); err != nil {
		return nil, err
	}

	format = strings.TrimSpace(format)
	if format == "" {
		format = "unknown"
	}

	ctx, cancel := s.ctx()
	defer cancel()

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sbom_objects (sha256, storage_path, size_bytes, format, content_type, is_gzip)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (sha256) DO NOTHING`,
		sha,
		relativePath,
		len(data),
		format,
		strings.TrimSpace(contentType),
		isGzip,
	)
	if err != nil {
		return nil, err
	}

	return &SbomObject{
		SHA:         sha,
		Bytes:       data,
		StoragePath: relativePath,
		Format:      format,
		ContentType: strings.TrimSpace(contentType),
		IsGzip:      isGzip,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

func (s *PostgresStore) GetSbomBySHA(sha string) (*SbomObject, error) {
	meta, err := s.loadSbomMeta(sha)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(s.storageRoot, meta.StoragePath)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	meta.Bytes = data
	return meta, nil
}

func (s *PostgresStore) ListAllScopes() ([]models.Scope, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE archived_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	scopes := make([]models.Scope, 0)
	for rows.Next() {
		var scope models.Scope
		if err := rows.Scan(&scope.ID, &scope.ProductID, &scope.Name, &scope.Description, &scope.ArchivedAt, &scope.CreatedAt, &scope.UpdatedAt); err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return scopes, nil
}

func (s *PostgresStore) ListAllTests() ([]models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE archived_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tests := make([]models.Test, 0)
	for rows.Next() {
		var test models.Test
		var publicToken sql.NullString
		if err := rows.Scan(&test.ID, &test.ScopeID, &test.Name, &test.SbomStandard, &test.SbomSpecVersion, &test.IsPublic, &publicToken, &test.ArchivedAt, &test.CreatedAt, &test.UpdatedAt); err != nil {
			return nil, err
		}
		if publicToken.Valid {
			test.PublicToken = publicToken.String
		}
		tests = append(tests, test)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tests, nil
}

func (s *PostgresStore) ListUsers() ([]models.User, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at
		 FROM users
		 ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var user models.User
		var fullName sql.NullString
		if err := rows.Scan(&user.ID, &user.Email, &user.Role, &user.AccountType, &user.Nickname, &fullName, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		user.FullName = nullStringToString(fullName)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *PostgresStore) DeleteUser(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	result, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ensureProductExists(ctx context.Context, productID uuid.UUID) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`, productID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ensureScopeExists(ctx context.Context, scopeID uuid.UUID) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM scopes WHERE id = $1)`, scopeID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) ensureTestExists(ctx context.Context, testID uuid.UUID) error {
	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`, testID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func ensureTestExistsTx(ctx context.Context, tx *sql.Tx, testID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`, testID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) createTest(scopeID uuid.UUID, name, sbomStandard, sbomSpecVersion string) (*models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO tests (scope_id, name, sbom_standard, sbom_spec_version)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (scope_id, LOWER(name), sbom_standard, sbom_spec_version) DO NOTHING
		 RETURNING id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at`,
		scopeID,
		name,
		sbomStandard,
		sbomSpecVersion,
	)
	test, err := scanTest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	return test, nil
}

func sbomRelativePath(sha string) (string, error) {
	if len(sha) < 4 {
		return "", ErrInvalidPayload
	}
	return filepath.Join(sha[:2], sha[2:4], sha), nil
}

func writeFileIfMissing(path string, data []byte) error {
	file, err := openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func (s *PostgresStore) loadSbomMeta(sha string) (*SbomObject, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var obj SbomObject
	var storagePath string
	if err := s.db.QueryRowContext(ctx,
		`SELECT sha256, storage_path, content_type, is_gzip, format, created_at
		 FROM sbom_objects
		 WHERE sha256 = $1`, sha).Scan(&obj.SHA, &storagePath, &obj.ContentType, &obj.IsGzip, &obj.Format, &obj.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	obj.ContentType = strings.TrimSpace(obj.ContentType)
	obj.Format = strings.TrimSpace(obj.Format)
	obj.StoragePath = storagePath
	obj.Bytes = nil
	return &obj, nil
}

func collectSbomSHAs(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	shas := make([]string, 0)
	for rows.Next() {
		var sha string
		if err := rows.Scan(&sha); err != nil {
			return nil, err
		}
		if sha != "" {
			shas = append(shas, sha)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return shas, nil
}

func (s *PostgresStore) cleanupSbomObjects(ctx context.Context, shas []string) error {
	if len(shas) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	for _, sha := range shas {
		sha = strings.TrimSpace(sha)
		if sha == "" {
			continue
		}
		if _, ok := seen[sha]; ok {
			continue
		}
		seen[sha] = struct{}{}

		var remaining int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(1) FROM test_revisions WHERE sbom_sha256 = $1`, sha).Scan(&remaining); err != nil {
			return err
		}
		if remaining > 0 {
			continue
		}

		var storagePath string
		if err := s.db.QueryRowContext(ctx,
			`SELECT storage_path FROM sbom_objects WHERE sha256 = $1`, sha).Scan(&storagePath); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}

		if _, err := s.db.ExecContext(ctx, `DELETE FROM sbom_objects WHERE sha256 = $1`, sha); err != nil {
			return err
		}
		if storagePath != "" {
			path := filepath.Join(s.storageRoot, storagePath)
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
