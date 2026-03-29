package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newMockStore(t *testing.T) (*PostgresStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	store, err := NewPostgresStore(db, t.TempDir())
	if err != nil {
		t.Fatalf("new postgres store: %v", err)
	}
	return store, mock
}

func expectDefaultProjectLookup(mock sqlmock.Sqlmock, projectID uuid.UUID) {
	expectQuery(mock, `SELECT id
		 FROM projects
		 WHERE LOWER(name) = LOWER($1)
		 LIMIT 1`).
		WithArgs(defaultProjectName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(projectID))
}

func expectProjectExists(mock sqlmock.Sqlmock, projectID uuid.UUID) {
	expectQuery(mock, `SELECT EXISTS(
		   SELECT 1
		   FROM projects
		   WHERE id = $1
		 )`).
		WithArgs(projectID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
}
func expectQuery(mock sqlmock.Sqlmock, query string) *sqlmock.ExpectedQuery {
	return mock.ExpectQuery(normalizeQuery(query))
}
func expectExec(mock sqlmock.Sqlmock, query string) *sqlmock.ExpectedExec {
	return mock.ExpectExec(normalizeQuery(query))
}
func normalizeQuery(query string) string {
	parts := strings.Fields(query)
	for i, part := range parts {
		parts[i] = regexp.QuoteMeta(part)
	}
	return strings.Join(parts, `\s+`)
}
func TestNewPostgresStore(t *testing.T) {
	if _, err := NewPostgresStore(nil, t.TempDir()); err == nil {
		t.Fatalf("expected nil db error")
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectClose()
	if _, err := NewPostgresStore(db, " "); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload, got %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	db, mock, err = sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectClose()
	if _, err := NewPostgresStore(db, "/proc/ctwall-denied"); err == nil {
		t.Fatalf("expected mkdir failure")
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
	db, mock, err = sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	mock.ExpectClose()
	store, err := NewPostgresStore(db, t.TempDir())
	if err != nil {
		t.Fatalf("unexpected store error: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestPgErrorHelpers(t *testing.T) {
	if !isUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Fatalf("expected unique violation")
	}
	if isUniqueViolation(errors.New("boom")) {
		t.Fatalf("expected no unique violation")
	}
	if !isForeignKeyViolation(&pgconn.PgError{Code: "23503"}) {
		t.Fatalf("expected foreign key violation")
	}
	if isForeignKeyViolation(errors.New("boom")) {
		t.Fatalf("expected no foreign key violation")
	}
}
func TestSbomRelativePath(t *testing.T) {
	if _, err := sbomRelativePath("abc"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	path, err := sbomRelativePath("abcdef")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if path != filepath.Join("ab", "cd", "abcdef") {
		t.Fatalf("unexpected path: %s", path)
	}
}
func TestWriteFileIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := writeFileIfMissing(path, []byte("data")); err != nil {
		t.Fatalf("write file: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(contents) != "data" {
		t.Fatalf("unexpected contents: %s", contents)
	}
	if err := writeFileIfMissing(path, []byte("data")); err != nil {
		t.Fatalf("expected no error on existing file, got %v", err)
	}
	origOpenFile := openFile
	openFile = func(string, int, os.FileMode) (fileWriter, error) {
		return failingWriter{}, nil
	}
	defer func() {
		openFile = origOpenFile
	}()
	if err := writeFileIfMissing(filepath.Join(dir, "fail.txt"), []byte("data")); err == nil {
		t.Fatalf("expected write error")
	}
	openFile = func(string, int, os.FileMode) (fileWriter, error) {
		return nil, errors.New("open failed")
	}
	if err := writeFileIfMissing(filepath.Join(dir, "open-fail.txt"), []byte("data")); err == nil {
		t.Fatalf("expected open error")
	}
}
func TestScanUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		userID := uuid.New()
		now := time.Now()
		query := `SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at`
		expectQuery(mock, query).
			WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
				AddRow(userID, "user@example.com", "ADMIN", "USER", "user", "User", now, now))
		row := db.QueryRow(query)
		user, err := scanUser(row)
		if err != nil || user.ID != userID {
			t.Fatalf("expected scan user success")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("scan error", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		query := `SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at`
		expectQuery(mock, query).
			WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
				AddRow("bad", "user@example.com", "ADMIN", "USER", "user", "User", time.Now(), time.Now()))
		row := db.QueryRow(query)
		if _, err := scanUser(row); err == nil {
			t.Fatalf("expected scan error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestGetUserByEmailAndID(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.GetUserByEmail(" "); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	userID := uuid.New()
	now := time.Now()
	queryByEmail := `SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at, password_hash
		 FROM users
		 WHERE LOWER(email) = LOWER($1)
		 LIMIT 1`
	expectQuery(mock, queryByEmail).
		WithArgs("missing@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at", "password_hash"}))
	if _, err := store.GetUserByEmail("missing@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, queryByEmail).
		WithArgs("user@example.com").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at", "password_hash"}).
			AddRow(userID, "user@example.com", "ADMIN", "USER", "user", "User", now, now, "hash"))
	creds, err := store.GetUserByEmail("user@example.com")
	if err != nil || creds.User.ID != userID || creds.PasswordHash != "hash" {
		t.Fatalf("expected user credentials")
	}
	queryByID := `SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at
		 FROM users
		 WHERE id = $1`
	missingID := uuid.New()
	expectQuery(mock, queryByID).
		WithArgs(missingID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}))
	if _, err := store.GetUserByID(missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, queryByID).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(userID, "user@example.com", "ADMIN", "USER", "user", "User", now, now))
	if user, err := store.GetUserByID(userID); err != nil || user.ID != userID {
		t.Fatalf("expected user")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateUser(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateUser(" ", "hash", "ADMIN", "USER", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	mock.ExpectBegin()
	query := `INSERT INTO users (email, password_hash, role, account_type, nickname, full_name)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (email) DO NOTHING
		 RETURNING id, email, role, account_type, nickname, full_name, created_at, updated_at`
	expectQuery(mock, query).
		WithArgs("exists@example.com", "hash", "ADMIN", "USER", "exists-nick", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}))
	mock.ExpectRollback()
	if _, err := store.CreateUser("exists@example.com", "hash", "ADMIN", "USER", "exists-nick", ""); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists")
	}
	userID := uuid.New()
	projectID := uuid.New()
	now := time.Now()
	mock.ExpectBegin()
	expectQuery(mock, query).
		WithArgs("user@example.com", "hash", "ADMIN", "USER", "user-nick", "User").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(userID, "user@example.com", "ADMIN", "USER", "user-nick", "User", now, now))
	expectQuery(mock, `SELECT id
		 FROM projects
		 WHERE LOWER(name) = LOWER($1)
		 LIMIT 1`).
		WithArgs(defaultProjectName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(projectID))
	expectExec(mock, `INSERT INTO project_memberships (project_id, user_id, project_role, created_by)
		 VALUES ($1, $2,
		         CASE
		           WHEN UPPER($3) = 'ADMIN' THEN 'ADMIN'
		           WHEN UPPER($3) = 'WRITER' THEN 'WRITER'
		           ELSE 'READER'
		         END,
		         NULL)
		 ON CONFLICT (project_id, user_id) DO NOTHING`).
		WithArgs(projectID, userID, "ADMIN").
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectExec(mock, `INSERT INTO user_settings (user_id, selected_project_id, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (user_id) DO UPDATE
		 SET selected_project_id = EXCLUDED.selected_project_id,
		     updated_at = NOW()`).
		WithArgs(userID, projectID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	user, err := store.CreateUser("user@example.com", "hash", "ADMIN", "USER", "user-nick", "User")
	if err != nil || user.ID != userID {
		t.Fatalf("expected user create")
	}
	noneUserID := uuid.New()
	mock.ExpectBegin()
	expectQuery(mock, query).
		WithArgs("none@example.com", "hash", "NONE", "USER", "none-nick", "No Access").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(noneUserID, "none@example.com", "NONE", "USER", "none-nick", "No Access", now, now))
	expectQuery(mock, `SELECT id
		 FROM projects
		 WHERE LOWER(name) = LOWER($1)
		 LIMIT 1`).
		WithArgs(defaultProjectName).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(projectID))
	expectExec(mock, `INSERT INTO user_settings (user_id, selected_project_id, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (user_id) DO UPDATE
		 SET selected_project_id = EXCLUDED.selected_project_id,
		     updated_at = NOW()`).
		WithArgs(noneUserID, nil).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	noneUser, err := store.CreateUser("none@example.com", "hash", "NONE", "USER", "none-nick", "No Access")
	if err != nil || noneUser.ID != noneUserID || noneUser.Role != "NONE" {
		t.Fatalf("expected none user create without project access")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestUpdateUser(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.UpdateUser(uuid.Nil, "ADMIN", "USER", "User"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if _, err := store.UpdateUser(uuid.New(), " ", "USER", "User"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if _, err := store.UpdateUser(uuid.New(), "ADMIN", " ", "User"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	updateQuery := `UPDATE users
		 SET role = $2,
		     account_type = $3,
		     nickname = $4,
		     full_name = $5,
		     updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, email, role, account_type, nickname, full_name, created_at, updated_at`
	missingID := uuid.New()
	expectQuery(mock, updateQuery).
		WithArgs(missingID, "WRITER", "USER", "missing-user", "Missing User").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}))
	if _, err := store.UpdateUser(missingID, "WRITER", "USER", "missing-user", "Missing User"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}

	userID := uuid.New()
	now := time.Now()
	expectQuery(mock, updateQuery).
		WithArgs(userID, "READER", "SERVICE_ACCOUNT", "updated-user", "Updated User").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(userID, "existing@example.com", "READER", "SERVICE_ACCOUNT", "updated-user", "Updated User", now, now))
	user, err := store.UpdateUser(userID, "READER", "SERVICE_ACCOUNT", "updated-user", "Updated User")
	if err != nil || user.ID != userID || user.Email != "existing@example.com" {
		t.Fatalf("expected updated user")
	}
	noneID := uuid.New()
	mock.ExpectBegin()
	expectQuery(mock, updateQuery).
		WithArgs(noneID, "NONE", "USER", "no-access-user", "No Access User").
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(noneID, "none@example.com", "NONE", "USER", "no-access-user", "No Access User", now, now))
	expectExec(mock, `DELETE FROM project_memberships WHERE user_id = $1`).
		WithArgs(noneID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	expectExec(mock, `UPDATE user_settings
			 SET selected_project_id = NULL,
			     updated_at = NOW()
			 WHERE user_id = $1`).
		WithArgs(noneID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	noneUser, err := store.UpdateUser(noneID, "NONE", "USER", "no-access-user", "No Access User")
	if err != nil || noneUser.ID != noneID || noneUser.Role != "NONE" {
		t.Fatalf("expected none role update with membership cleanup")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestCreateAPIToken(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateAPIToken(uuid.Nil, "name", "hash", nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid user")
	}
	if _, err := store.CreateAPIToken(uuid.New(), " ", "hash", nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid name")
	}
	if _, err := store.CreateAPIToken(uuid.New(), "name", " ", nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid hash")
	}
	userID := uuid.New()
	tokenID := uuid.New()
	now := time.Now()
	query := `INSERT INTO api_tokens (user_id, name, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, user_id, name, token_hash, last_used_at, expires_at, created_at`
	expectQuery(mock, query).
		WithArgs(userID, "token-name", "token-hash", nil).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "name", "token_hash", "last_used_at", "expires_at", "created_at"}).
			AddRow(tokenID, userID, "token-name", "token-hash", nil, nil, now))
	token, err := store.CreateAPIToken(userID, "token-name", "token-hash", nil)
	if err != nil || token.ID != tokenID {
		t.Fatalf("expected token create")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestGetAPITokenByHash(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, _, err := store.GetAPITokenByHash(" "); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	query := `SELECT t.id, t.user_id, t.name, t.token_hash, t.last_used_at, t.expires_at, t.created_at,
		        u.id, u.email, u.role, u.account_type, u.nickname, u.full_name, u.created_at, u.updated_at
		 FROM api_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1`
	expectQuery(mock, query).
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "name", "token_hash", "last_used_at", "expires_at", "created_at",
			"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at",
		}))
	if _, _, err := store.GetAPITokenByHash("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	tokenID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	expired := now.Add(-time.Minute)
	expectQuery(mock, query).
		WithArgs("expired").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "name", "token_hash", "last_used_at", "expires_at", "created_at",
			"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at",
		}).AddRow(tokenID, userID, "token", "expired", nil, expired, now, userID, "user@example.com", "WRITER", "USER", "user", "User", now, now))
	if _, _, err := store.GetAPITokenByHash("expired"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected expired not found")
	}
	expectQuery(mock, query).
		WithArgs("valid").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "name", "token_hash", "last_used_at", "expires_at", "created_at",
			"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at",
		}).AddRow(tokenID, userID, "token", "valid", nil, now.Add(time.Hour), now, userID, "user@example.com", "WRITER", "USER", "user", "User", now, now))
	updateLastUsed := `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if token, user, err := store.GetAPITokenByHash("valid"); err != nil || token.ID != tokenID || user.ID != userID {
		t.Fatalf("expected token")
	}
	expectQuery(mock, query).
		WithArgs("update-fail").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "name", "token_hash", "last_used_at", "expires_at", "created_at",
			"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at",
		}).AddRow(tokenID, userID, "token", "update-fail", nil, now.Add(time.Hour), now, userID, "user@example.com", "WRITER", "USER", "user", "User", now, now))
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnError(errors.New("boom"))
	if _, _, err := store.GetAPITokenByHash("update-fail"); err == nil {
		t.Fatalf("expected update error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateRefreshToken(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateRefreshToken(uuid.Nil, "hash", time.Now(), "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if _, err := store.CreateRefreshToken(uuid.New(), " ", time.Now(), "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid token hash")
	}
	if _, err := store.CreateRefreshToken(uuid.New(), "hash", time.Time{}, "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid expiry")
	}
	userID := uuid.New()
	tokenID := uuid.New()
	now := time.Now()
	expires := now.Add(72 * time.Hour)
	query := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`
	expectQuery(mock, query).
		WithArgs(userID, "refresh-hash", expires.UTC(), "ua", "ip").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "created_at", "last_used_at", "user_agent", "ip_address",
		}).AddRow(tokenID, userID, "refresh-hash", expires.UTC(), nil, nil, now, nil, "ua", "ip"))
	token, err := store.CreateRefreshToken(userID, "refresh-hash", expires, "ua", "ip")
	if err != nil || token.ID != tokenID {
		t.Fatalf("expected refresh token created")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestCreateRefreshTokenAndRevokeOthers(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateRefreshTokenAndRevokeOthers(uuid.Nil, "hash", time.Now(), "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if _, err := store.CreateRefreshTokenAndRevokeOthers(uuid.New(), " ", time.Now(), "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid token hash")
	}
	if _, err := store.CreateRefreshTokenAndRevokeOthers(uuid.New(), "hash", time.Time{}, "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid expiry")
	}

	userID := uuid.New()
	tokenID := uuid.New()
	now := time.Now()
	expires := now.Add(24 * time.Hour)

	mock.ExpectBegin()
	insertQuery := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`
	expectQuery(mock, insertQuery).
		WithArgs(userID, "refresh-hash", expires.UTC(), "ua", "ip").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "created_at", "last_used_at", "user_agent", "ip_address",
		}).AddRow(tokenID, userID, "refresh-hash", expires.UTC(), nil, nil, now, nil, "ua", "ip"))
	updateQuery := `UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE user_id = $1
		   AND id <> $2
		   AND revoked_at IS NULL
		   AND expires_at > NOW()`
	expectExec(mock, updateQuery).
		WithArgs(userID, tokenID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectCommit()

	token, err := store.CreateRefreshTokenAndRevokeOthers(userID, "refresh-hash", expires, "ua", "ip")
	if err != nil || token.ID != tokenID {
		t.Fatalf("expected refresh token created")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestRotateRefreshToken(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, _, err := store.RotateRefreshToken(" ", "new", time.Now(), "", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	currentID := uuid.New()
	newID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	expires := now.Add(72 * time.Hour)
	mock.ExpectBegin()
	selectQuery := `SELECT t.id, t.user_id, t.token_hash, t.expires_at, t.revoked_at, t.replaced_by_id, t.created_at, t.last_used_at, t.user_agent, t.ip_address,
		        u.id, u.email, u.role, u.account_type, u.nickname, u.full_name, u.created_at, u.updated_at
		 FROM refresh_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1
		 FOR UPDATE`
	expectQuery(mock, selectQuery).
		WithArgs("old-hash").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "created_at", "last_used_at", "user_agent", "ip_address",
			"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at",
		}).AddRow(currentID, userID, "old-hash", expires.UTC(), nil, nil, now, nil, "ua", "ip",
			userID, "user@example.com", "ADMIN", "USER", "user", "User", now, now))
	insertQuery := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`
	expectQuery(mock, insertQuery).
		WithArgs(userID, "new-hash", expires.UTC(), "ua2", "ip2").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "user_id", "token_hash", "expires_at", "revoked_at", "replaced_by_id", "created_at", "last_used_at", "user_agent", "ip_address",
		}).AddRow(newID, userID, "new-hash", expires.UTC(), nil, nil, now, nil, "ua2", "ip2"))
	updateQuery := `UPDATE refresh_tokens
		 SET revoked_at = NOW(), replaced_by_id = $1, last_used_at = NOW()
		 WHERE id = $2`
	expectExec(mock, updateQuery).
		WithArgs(newID, currentID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	token, user, err := store.RotateRefreshToken("old-hash", "new-hash", expires, "ua2", "ip2")
	if err != nil || token.ID != newID || user.ID != userID {
		t.Fatalf("expected refresh rotation success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestUpdateUserPassword(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if err := store.UpdateUserPassword(uuid.Nil, "hash"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	if err := store.UpdateUserPassword(uuid.New(), " "); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	userID := uuid.New()
	updateQuery := `UPDATE users
		 SET password_hash = $1, updated_at = NOW()
		 WHERE id = $2`
	expectExec(mock, updateQuery).
		WithArgs("new-hash", userID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.UpdateUserPassword(userID, "new-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}

	expectExec(mock, updateQuery).
		WithArgs("new-hash", userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.UpdateUserPassword(userID, "new-hash"); err != nil {
		t.Fatalf("expected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestRevokeRefreshToken(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if err := store.RevokeRefreshToken(" "); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	updateQuery := `UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE token_hash = $1
		   AND revoked_at IS NULL`
	expectExec(mock, updateQuery).
		WithArgs("token-hash").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.RevokeRefreshToken("token-hash"); err != nil {
		t.Fatalf("expected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestRevokeRefreshTokensForUser(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if err := store.RevokeRefreshTokensForUser(uuid.Nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	userID := uuid.New()
	updateQuery := `UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE user_id = $1
		   AND revoked_at IS NULL`
	expectExec(mock, updateQuery).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 2))
	if err := store.RevokeRefreshTokensForUser(userID); err != nil {
		t.Fatalf("expected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestUpdateAPITokenLastUsed(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	tokenID := uuid.New()
	updateLastUsed := `UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnError(errors.New("boom"))
	if err := store.UpdateAPITokenLastUsed(tokenID); err == nil {
		t.Fatalf("expected update error")
	}
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.UpdateAPITokenLastUsed(tokenID); err == nil {
		t.Fatalf("expected rows error")
	}
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.UpdateAPITokenLastUsed(tokenID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectExec(mock, updateLastUsed).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.UpdateAPITokenLastUsed(tokenID); err != nil {
		t.Fatalf("expected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateAuditLog(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	entry := AuditLogEntry{
		Action:     "LOGIN_SUCCESS",
		EntityType: "AUTH",
		Details:    []byte(`{"category":"authn","severity":"INFO","min_role":"read","event_key":"authn.login_success"}`),
		IPAddress:  "127.0.0.1",
	}
	insertAudit := `INSERT INTO audit_logs (actor_id, action, entity_type, entity_id, details, ip_address)
		 VALUES ($1, $2, $3, $4, $5, $6)`
	expectExec(mock, insertAudit).
		WithArgs(entry.ActorID, entry.Action, entry.EntityType, entry.EntityID, sqlmock.AnyArg(), entry.IPAddress).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.CreateAuditLog(entry); err != nil {
		t.Fatalf("expected audit log insert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestListAuditLogs(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.ListAuditLogs(" ", nil, "", 10, 0); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}

	sourceID := uuid.New()
	logID := uuid.New()
	now := time.Now()
	details := []byte(`{"sync_id":"abc","mode":"full"}`)
	query := `SELECT id, actor_id, action, entity_type, entity_id, details, ip_address, created_at
		FROM audit_logs
		WHERE entity_type = $1 AND entity_id = $2 AND action LIKE $3
		ORDER BY created_at DESC LIMIT $4 OFFSET $5`
	expectQuery(mock, query).
		WithArgs("malware_source", sourceID, "MALWARE_OSV_SYNC_%", 25, 0).
		WillReturnRows(sqlmock.NewRows([]string{
			"id",
			"actor_id",
			"action",
			"entity_type",
			"entity_id",
			"details",
			"ip_address",
			"created_at",
		}).AddRow(logID, nil, "MALWARE_OSV_SYNC_START", "malware_source", sourceID, details, "127.0.0.1", now))

	logs, err := store.ListAuditLogs("malware_source", &sourceID, "MALWARE_OSV_SYNC_", 25, 0)
	if err != nil {
		t.Fatalf("expected logs, got %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].ID != logID || logs[0].Action != "MALWARE_OSV_SYNC_START" {
		t.Fatalf("unexpected log entry: %+v", logs[0])
	}
	if logs[0].EntityID == nil || *logs[0].EntityID != sourceID {
		t.Fatalf("expected entity id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
func (failingWriter) Close() error {
	return nil
}
func TestEnsureProduct(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, _, err := store.EnsureProduct(" ", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	projectID := uuid.New()
	productID := uuid.New()
	now := time.Now()
	selectByName := `SELECT id, project_id, name, description, archived_at, created_at, updated_at
			 FROM products
			 WHERE project_id = $1
			   AND LOWER(name) = LOWER($2)
			 LIMIT 1`
	insertProduct := `INSERT INTO products (project_id, name, description)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (project_id, LOWER(name)) DO NOTHING
			 RETURNING id, project_id, name, description, archived_at, created_at, updated_at`
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Alpha").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(productID, projectID, "Alpha", "desc", nil, now, now))
	got, created, err := store.EnsureProduct("Alpha", "desc")
	if err != nil || created || got.ID != productID {
		t.Fatalf("expected existing product, got %v created=%v err=%v", got, created, err)
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Beta").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Beta", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), projectID, "Beta", "", nil, now, now))
	got, created, err = store.EnsureProduct("Beta", "")
	if err != nil || !created || got.Name != "Beta" {
		t.Fatalf("expected created product, got %v created=%v err=%v", got, created, err)
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Gamma").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Gamma", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Gamma").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(productID, projectID, "Gamma", "", nil, now, now))
	got, created, err = store.EnsureProduct("Gamma", "")
	if err != nil || created || got.Name != "Gamma" {
		t.Fatalf("expected conflict product, got %v created=%v err=%v", got, created, err)
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Retry").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Retry", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Retry").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureProduct("Retry", ""); err == nil {
		t.Fatalf("expected reselect error")
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Error").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Error", "").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureProduct("Error", ""); err == nil {
		t.Fatalf("expected create error")
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, selectByName).
		WithArgs(projectID, "Delta").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureProduct("Delta", ""); err == nil {
		t.Fatalf("expected error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateProductAndGetProduct(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateProduct(" ", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	projectID := uuid.New()
	insertProduct := `INSERT INTO products (project_id, name, description)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (project_id, LOWER(name)) DO NOTHING
			 RETURNING id, project_id, name, description, archived_at, created_at, updated_at`
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Alpha", "desc").
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateProduct("Alpha", "desc"); err == nil {
		t.Fatalf("expected insert error")
	}
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Beta", "desc").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	if _, err := store.CreateProduct("Beta", "desc"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists")
	}
	productID := uuid.New()
	now := time.Now()
	expectDefaultProjectLookup(mock, projectID)
	expectProjectExists(mock, projectID)
	expectQuery(mock, insertProduct).
		WithArgs(projectID, "Gamma", "desc").
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(productID, projectID, "Gamma", "desc", nil, now, now))
	if product, err := store.CreateProduct("Gamma", "desc"); err != nil || product.ID != productID {
		t.Fatalf("expected product created, got %v err=%v", product, err)
	}
	selectByID := `SELECT id, project_id, name, description, archived_at, created_at, updated_at
			 FROM products
			 WHERE id = $1 `
	missingID := uuid.New()
	expectQuery(mock, selectByID).
		WithArgs(missingID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	if _, err := store.GetProduct(missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, selectByID).
		WithArgs(productID).
		WillReturnError(errors.New("boom"))
	if _, err := store.GetProduct(productID); err == nil {
		t.Fatalf("expected get error")
	}
	expectQuery(mock, selectByID).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(productID, projectID, "Gamma", "desc", nil, now, now))
	if product, err := store.GetProduct(productID); err != nil || product.ID != productID {
		t.Fatalf("expected get success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestUpdateProject(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()

	if _, err := store.UpdateProject(uuid.Nil, "Alpha", "desc"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload for nil id")
	}
	if _, err := store.UpdateProject(uuid.New(), " ", "desc"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload for empty name")
	}

	projectID := uuid.New()
	query := `UPDATE projects
		 SET name = $2,
		     description = $3,
		     updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, name, description, archived_at, created_by, created_at, updated_at`

	expectQuery(mock, query).
		WithArgs(projectID, "Missing", "desc").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "archived_at", "created_by", "created_at", "updated_at"}))
	if _, err := store.UpdateProject(projectID, "Missing", "desc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}

	expectQuery(mock, query).
		WithArgs(projectID, "Conflict", "desc").
		WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := store.UpdateProject(projectID, "Conflict", "desc"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists, got %v", err)
	}

	expectQuery(mock, query).
		WithArgs(projectID, "Boom", "desc").
		WillReturnError(errors.New("boom"))
	if _, err := store.UpdateProject(projectID, "Boom", "desc"); err == nil {
		t.Fatalf("expected generic error")
	}

	now := time.Now()
	expectQuery(mock, query).
		WithArgs(projectID, "Alpha", "updated description").
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "description", "archived_at", "created_by", "created_at", "updated_at"}).
			AddRow(projectID, "Alpha", "updated description", nil, nil, now, now))
	project, err := store.UpdateProject(projectID, "Alpha", "updated description")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if project.ID != projectID || project.Name != "Alpha" || project.Description != "updated description" {
		t.Fatalf("unexpected project: %+v", project)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestListAndDeleteProducts(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	listProducts := `SELECT id, project_id, name, description, archived_at, created_at, updated_at
			 FROM products
			 WHERE archived_at IS NULL
			 ORDER BY name`
	expectQuery(mock, listProducts).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListProducts(); err == nil {
		t.Fatalf("expected list error")
	}
	expectQuery(mock, listProducts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow("bad", uuid.New(), "Alpha", "desc", nil, time.Now(), time.Now()))
	if _, err := store.ListProducts(); err == nil {
		t.Fatalf("expected scan error")
	}
	expectQuery(mock, listProducts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), uuid.New(), "Alpha", "desc", nil, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListProducts(); err == nil {
		t.Fatalf("expected rows error")
	}
	productID := uuid.New()
	projectID := uuid.New()
	now := time.Now()
	expectQuery(mock, listProducts).
		WillReturnRows(sqlmock.NewRows([]string{"id", "project_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(productID, projectID, "Alpha", "desc", nil, now, now))
	products, err := store.ListProducts()
	if err != nil || len(products) != 1 {
		t.Fatalf("expected product list")
	}
	collectShas := `SELECT DISTINCT tr.sbom_sha256
		 FROM test_revisions tr
		 JOIN tests t ON tr.test_id = t.id
		 JOIN scopes s ON t.scope_id = s.id
		 WHERE s.product_id = $1`
	deleteProduct := `DELETE FROM products WHERE id = $1`
	expectQuery(mock, collectShas).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteProduct).
		WithArgs(productID).
		WillReturnError(errors.New("boom"))
	if err := store.DeleteProduct(productID); err == nil {
		t.Fatalf("expected delete error")
	}
	expectQuery(mock, collectShas).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteProduct).
		WithArgs(productID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.DeleteProduct(productID); err == nil {
		t.Fatalf("expected rows affected error")
	}
	expectQuery(mock, collectShas).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteProduct).
		WithArgs(productID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.DeleteProduct(productID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, collectShas).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteProduct).
		WithArgs(productID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteProduct(productID); err != nil {
		t.Fatalf("expected delete success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestEnsureProductExists(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	productID := uuid.New()
	existsQuery := `SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnError(errors.New("boom"))
	if err := store.ensureProductExists(context.Background(), productID); err == nil {
		t.Fatalf("expected error")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := store.ensureProductExists(context.Background(), productID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	if err := store.ensureProductExists(context.Background(), productID); err != nil {
		t.Fatalf("expected exists success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestEnsureScopeAndCreateScope(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	productID := uuid.New()
	scopeID := uuid.New()
	now := time.Now()
	if _, _, err := store.EnsureScope(productID, " ", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	existsQuery := `SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`
	selectScopeByName := `SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE product_id = $1 AND LOWER(name) = LOWER($2)
		 LIMIT 1`
	insertScope := `INSERT INTO scopes (product_id, name, description)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (product_id, LOWER(name))  DO NOTHING
		 RETURNING id, product_id, name, description, archived_at, created_at, updated_at`
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, _, err := store.EnsureScope(productID, "Core", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Core").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(scopeID, productID, "Core", "", nil, now, now))
	scope, created, err := store.EnsureScope(productID, "Core", "")
	if err != nil || created || scope.ID != scopeID {
		t.Fatalf("expected existing scope")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Payments").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertScope).
		WithArgs(productID, "Payments", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), productID, "Payments", "", nil, now, now))
	scope, created, err = store.EnsureScope(productID, "Payments", "")
	if err != nil || !created || scope.Name != "Payments" {
		t.Fatalf("expected created scope")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Ops").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertScope).
		WithArgs(productID, "Ops", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Ops").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(scopeID, productID, "Ops", "", nil, now, now))
	scope, created, err = store.EnsureScope(productID, "Ops", "")
	if err != nil || created || scope.Name != "Ops" {
		t.Fatalf("expected conflict scope")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Retry").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertScope).
		WithArgs(productID, "Retry", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Retry").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureScope(productID, "Retry", ""); err == nil {
		t.Fatalf("expected reselect error")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Error").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertScope).
		WithArgs(productID, "Error", "").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureScope(productID, "Error", ""); err == nil {
		t.Fatalf("expected create error")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectScopeByName).
		WithArgs(productID, "Fail").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureScope(productID, "Fail", ""); err == nil {
		t.Fatalf("expected select error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateScopeErrorsAndGetScope(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.CreateScope(uuid.New(), " ", ""); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	productID := uuid.New()
	insertScope := `INSERT INTO scopes (product_id, name, description)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (product_id, LOWER(name))  DO NOTHING
		 RETURNING id, product_id, name, description, archived_at, created_at, updated_at`
	expectQuery(mock, insertScope).
		WithArgs(productID, "Core", "").
		WillReturnError(&pgconn.PgError{Code: "23503"})
	if _, err := store.CreateScope(productID, "Core", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected foreign key not found")
	}
	expectQuery(mock, insertScope).
		WithArgs(productID, "Core", "").
		WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := store.CreateScope(productID, "Core", ""); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected unique conflict")
	}
	expectQuery(mock, insertScope).
		WithArgs(productID, "Core", "").
		WillReturnError(errors.New("boom"))
	if _, err := store.CreateScope(productID, "Core", ""); err == nil {
		t.Fatalf("expected insert error")
	}
	expectQuery(mock, insertScope).
		WithArgs(productID, "Core", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	if _, err := store.CreateScope(productID, "Core", ""); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists")
	}
	scopeID := uuid.New()
	now := time.Now()
	expectQuery(mock, insertScope).
		WithArgs(productID, "Core", "").
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(scopeID, productID, "Core", "", nil, now, now))
	if scope, err := store.CreateScope(productID, "Core", ""); err != nil || scope.ID != scopeID {
		t.Fatalf("expected scope created")
	}
	selectScopeByID := `SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE id = $1 `
	missingScope := uuid.New()
	expectQuery(mock, selectScopeByID).
		WithArgs(missingScope).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}))
	if _, err := store.GetScope(missingScope); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, selectScopeByID).
		WithArgs(scopeID).
		WillReturnError(errors.New("boom"))
	if _, err := store.GetScope(scopeID); err == nil {
		t.Fatalf("expected get error")
	}
	expectQuery(mock, selectScopeByID).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(scopeID, productID, "Core", "", nil, now, now))
	if scope, err := store.GetScope(scopeID); err != nil || scope.ID != scopeID {
		t.Fatalf("expected get scope")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestListAndDeleteScopes(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	productID := uuid.New()
	existsQuery := `SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`
	listScopes := `SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE product_id = $1  AND archived_at IS NULL
		 ORDER BY name`
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, err := store.ListScopes(productID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listScopes).
		WithArgs(productID).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListScopes(productID); err == nil {
		t.Fatalf("expected list error")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listScopes).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow("bad", productID, "Core", "", nil, time.Now(), time.Now()))
	if _, err := store.ListScopes(productID); err == nil {
		t.Fatalf("expected scan error")
	}
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listScopes).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), productID, "Core", "", nil, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListScopes(productID); err == nil {
		t.Fatalf("expected rows error")
	}
	scopeID := uuid.New()
	now := time.Now()
	expectQuery(mock, existsQuery).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listScopes).
		WithArgs(productID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(scopeID, productID, "Core", "", nil, now, now))
	scopes, err := store.ListScopes(productID)
	if err != nil || len(scopes) != 1 {
		t.Fatalf("expected scopes list")
	}
	collectShas := `SELECT DISTINCT tr.sbom_sha256
		 FROM test_revisions tr
		 JOIN tests t ON tr.test_id = t.id
		 WHERE t.scope_id = $1`
	deleteScope := `DELETE FROM scopes WHERE id = $1`
	expectQuery(mock, collectShas).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteScope).
		WithArgs(scopeID).
		WillReturnError(errors.New("boom"))
	if err := store.DeleteScope(scopeID); err == nil {
		t.Fatalf("expected delete error")
	}
	expectQuery(mock, collectShas).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteScope).
		WithArgs(scopeID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.DeleteScope(scopeID); err == nil {
		t.Fatalf("expected rows affected error")
	}
	expectQuery(mock, collectShas).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteScope).
		WithArgs(scopeID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.DeleteScope(scopeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, collectShas).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteScope).
		WithArgs(scopeID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteScope(scopeID); err != nil {
		t.Fatalf("expected delete success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestEnsureTestAndCreateTest(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	scopeID := uuid.New()
	testID := uuid.New()
	now := time.Now()
	if _, _, err := store.EnsureTest(scopeID, " ", "cyclonedx", "1.6"); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	existsScope := `SELECT EXISTS(SELECT 1 FROM scopes WHERE id = $1)`
	selectTestByName := `SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE scope_id = $1 AND LOWER(name) = LOWER($2)
		   AND sbom_standard = $3 AND sbom_spec_version = $4
		 LIMIT 1`
	insertTest := `INSERT INTO tests (scope_id, name, sbom_standard, sbom_spec_version)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (scope_id, LOWER(name), sbom_standard, sbom_spec_version)  DO NOTHING
		 RETURNING id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at`
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, _, err := store.EnsureTest(scopeID, "Gateway", "cyclonedx", "1.6"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(testID, scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, now, now))
	testItem, created, err := store.EnsureTest(scopeID, "Gateway", "cyclonedx", "1.6")
	if err != nil || created || testItem.ID != testID {
		t.Fatalf("expected existing test")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Api", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Api", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), scopeID, "Api", "cyclonedx", "1.6", false, "", nil, now, now))
	testItem, created, err = store.EnsureTest(scopeID, "Api", "cyclonedx", "1.6")
	if err != nil || !created || testItem.Name != "Api" {
		t.Fatalf("expected created test")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Ops", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Ops", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Ops", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(testID, scopeID, "Ops", "cyclonedx", "1.6", false, "", nil, now, now))
	testItem, created, err = store.EnsureTest(scopeID, "Ops", "cyclonedx", "1.6")
	if err != nil || created || testItem.Name != "Ops" {
		t.Fatalf("expected conflict test")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Retry", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Retry", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Retry", "cyclonedx", "1.6").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureTest(scopeID, "Retry", "cyclonedx", "1.6"); err == nil {
		t.Fatalf("expected reselect error")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Error", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Error", "cyclonedx", "1.6").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureTest(scopeID, "Error", "cyclonedx", "1.6"); err == nil {
		t.Fatalf("expected create error")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, selectTestByName).
		WithArgs(scopeID, "Fail", "cyclonedx", "1.6").
		WillReturnError(errors.New("boom"))
	if _, _, err := store.EnsureTest(scopeID, "Fail", "cyclonedx", "1.6"); err == nil {
		t.Fatalf("expected select error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateTestErrorsAndGetTest(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	scopeID := uuid.New()
	insertTest := `INSERT INTO tests (scope_id, name, sbom_standard, sbom_spec_version)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (scope_id, LOWER(name), sbom_standard, sbom_spec_version)  DO NOTHING
		 RETURNING id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at`
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnError(&pgconn.PgError{Code: "23503"})
	if _, err := store.createTest(scopeID, "Gateway", "cyclonedx", "1.6"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected foreign key error")
	}
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := store.createTest(scopeID, "Gateway", "cyclonedx", "1.6"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected unique error")
	}
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnError(errors.New("boom"))
	if _, err := store.createTest(scopeID, "Gateway", "cyclonedx", "1.6"); err == nil {
		t.Fatalf("expected insert error")
	}
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	if _, err := store.createTest(scopeID, "Gateway", "cyclonedx", "1.6"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("expected already exists")
	}
	testID := uuid.New()
	now := time.Now()
	expectQuery(mock, insertTest).
		WithArgs(scopeID, "Gateway", "cyclonedx", "1.6").
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(testID, scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, now, now))
	if testItem, err := store.createTest(scopeID, "Gateway", "cyclonedx", "1.6"); err != nil || testItem.ID != testID {
		t.Fatalf("expected created test")
	}
	selectTestByID := `SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE id = $1 `
	missingTest := uuid.New()
	expectQuery(mock, selectTestByID).
		WithArgs(missingTest).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}))
	if _, err := store.GetTest(missingTest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, selectTestByID).
		WithArgs(testID).
		WillReturnError(errors.New("boom"))
	if _, err := store.GetTest(testID); err == nil {
		t.Fatalf("expected get error")
	}
	expectQuery(mock, selectTestByID).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(testID, scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, now, now))
	if testItem, err := store.GetTest(testID); err != nil || testItem.ID != testID {
		t.Fatalf("expected get test")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestListAndDeleteTests(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	scopeID := uuid.New()
	existsScope := `SELECT EXISTS(SELECT 1 FROM scopes WHERE id = $1)`
	listTests := `SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE scope_id = $1  AND archived_at IS NULL
		 ORDER BY name`
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, err := store.ListTests(scopeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listTests).
		WithArgs(scopeID).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListTests(scopeID); err == nil {
		t.Fatalf("expected list error")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listTests).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow("bad", scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, time.Now(), time.Now()))
	if _, err := store.ListTests(scopeID); err == nil {
		t.Fatalf("expected scan error")
	}
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listTests).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListTests(scopeID); err == nil {
		t.Fatalf("expected rows error")
	}
	testID := uuid.New()
	now := time.Now()
	expectQuery(mock, existsScope).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listTests).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(testID, scopeID, "Gateway", "cyclonedx", "1.6", false, "", nil, now, now))
	tests, err := store.ListTests(scopeID)
	if err != nil || len(tests) != 1 {
		t.Fatalf("expected tests list")
	}
	collectShas := `SELECT DISTINCT sbom_sha256 FROM test_revisions WHERE test_id = $1`
	deleteTest := `DELETE FROM tests WHERE id = $1`
	expectQuery(mock, collectShas).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteTest).
		WithArgs(testID).
		WillReturnError(errors.New("boom"))
	if err := store.DeleteTest(testID); err == nil {
		t.Fatalf("expected delete error")
	}
	expectQuery(mock, collectShas).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteTest).
		WithArgs(testID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.DeleteTest(testID); err == nil {
		t.Fatalf("expected rows affected error")
	}
	expectQuery(mock, collectShas).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteTest).
		WithArgs(testID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.DeleteTest(testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, collectShas).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"sbom_sha256"}))
	expectExec(mock, deleteTest).
		WithArgs(testID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteTest(testID); err != nil {
		t.Fatalf("expected delete success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestEnsureScopeExistsAndTestExists(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	scopeID := uuid.New()
	testID := uuid.New()
	scopeExists := `SELECT EXISTS(SELECT 1 FROM scopes WHERE id = $1)`
	expectQuery(mock, scopeExists).
		WithArgs(scopeID).
		WillReturnError(errors.New("boom"))
	if err := store.ensureScopeExists(context.Background(), scopeID); err == nil {
		t.Fatalf("expected scope exists error")
	}
	expectQuery(mock, scopeExists).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := store.ensureScopeExists(context.Background(), scopeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected scope not found")
	}
	expectQuery(mock, scopeExists).
		WithArgs(scopeID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	if err := store.ensureScopeExists(context.Background(), scopeID); err != nil {
		t.Fatalf("expected scope exists")
	}
	testExists := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
	expectQuery(mock, testExists).
		WithArgs(testID).
		WillReturnError(errors.New("boom"))
	if err := store.ensureTestExists(context.Background(), testID); err == nil {
		t.Fatalf("expected test exists error")
	}
	expectQuery(mock, testExists).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if err := store.ensureTestExists(context.Background(), testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected test not found")
	}
	expectQuery(mock, testExists).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	if err := store.ensureTestExists(context.Background(), testID); err != nil {
		t.Fatalf("expected test exists")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestAddRevision(t *testing.T) {
	t.Run("begin error", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		store, err := NewPostgresStore(db, t.TempDir())
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		mock.ExpectBegin().WillReturnError(errors.New("boom"))
		if _, err := store.AddRevision(uuid.New(), RevisionInput{}); err == nil {
			t.Fatalf("expected begin error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("ensure test exists error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{}); err == nil {
			t.Fatalf("expected exists error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("test missing", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("update error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{}); err == nil {
			t.Fatalf("expected update error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("marshal error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		origMarshal := marshalJSON
		marshalJSON = func(any) ([]byte, error) {
			return nil, errors.New("boom")
		}
		defer func() { marshalJSON = origMarshal }()
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{Tags: []string{"a"}}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected invalid payload")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("insert error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		insertRevision := `INSERT INTO test_revisions (test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NOW())
		 RETURNING id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at`
		expectQuery(mock, insertRevision).
			WithArgs(testID, "sha", "syft", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{SbomSha256: "sha", SbomProducer: "syft"}); err == nil {
			t.Fatalf("expected insert error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("update test error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		revID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		insertRevision := `INSERT INTO test_revisions (test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NOW())
		 RETURNING id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at`
		expectQuery(mock, insertRevision).
			WithArgs(testID, "sha", "syft", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0).
			WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
				AddRow(revID, testID, "sha", "syft", []byte(`["v1"]`), nil, nil, 0, true, time.Now(), time.Now()))
		expectExec(mock, `INSERT INTO test_revision_malware_summary (revision_id)
		 VALUES ($1)
		 ON CONFLICT (revision_id) DO NOTHING`).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `INSERT INTO test_revision_malware_summary_queue (revision_id, status, reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (revision_id) DO UPDATE SET
		     status = EXCLUDED.status,
		     reason = EXCLUDED.reason,
		     updated_at = NOW(),
		     completed_at = NULL,
		     last_error = NULL`).
			WithArgs(revID, TestRevisionMalwareSummaryStatusPending, TestRevisionMalwareSummaryReasonIngest).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `UPDATE tests SET updated_at = NOW() WHERE id = $1`).
			WithArgs(testID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if _, err := store.AddRevision(testID, RevisionInput{SbomSha256: "sha", SbomProducer: "syft", Tags: []string{"v1"}}); err == nil {
			t.Fatalf("expected update test error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("commit error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		revID := uuid.New()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		insertRevision := `INSERT INTO test_revisions (test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NOW())
		 RETURNING id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at`
		expectQuery(mock, insertRevision).
			WithArgs(testID, "sha", "syft", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 0).
			WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
				AddRow(revID, testID, "sha", "syft", []byte(`["v1"]`), nil, nil, 0, true, time.Now(), time.Now()))
		expectExec(mock, `INSERT INTO test_revision_malware_summary (revision_id)
		 VALUES ($1)
		 ON CONFLICT (revision_id) DO NOTHING`).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `INSERT INTO test_revision_malware_summary_queue (revision_id, status, reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (revision_id) DO UPDATE SET
		     status = EXCLUDED.status,
		     reason = EXCLUDED.reason,
		     updated_at = NOW(),
		     completed_at = NULL,
		     last_error = NULL`).
			WithArgs(revID, TestRevisionMalwareSummaryStatusPending, TestRevisionMalwareSummaryReasonIngest).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `UPDATE tests SET updated_at = NOW() WHERE id = $1`).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit().WillReturnError(errors.New("boom"))
		if _, err := store.AddRevision(testID, RevisionInput{SbomSha256: "sha", SbomProducer: "syft", Tags: []string{"v1"}}); err == nil {
			t.Fatalf("expected commit error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		testID := uuid.New()
		revID := uuid.New()
		now := time.Now()
		mock.ExpectBegin()
		existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
		expectQuery(mock, existsTest).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		updateActive := `UPDATE test_revisions
		 SET is_active = FALSE
		 WHERE test_id = $1 AND is_active = TRUE`
		expectExec(mock, updateActive).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		insertRevision := `INSERT INTO test_revisions (test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, NOW())
		 RETURNING id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at`
		expectQuery(mock, insertRevision).
			WithArgs(testID, "sha", "syft", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), 2).
			WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
				AddRow(revID, testID, "sha", "syft", []byte(`["v1"]`), []byte(`{"a":"b"}`), nil, 2, true, now, now))
		expectExec(mock, `INSERT INTO test_revision_malware_summary (revision_id)
		 VALUES ($1)
		 ON CONFLICT (revision_id) DO NOTHING`).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `INSERT INTO test_revision_malware_summary_queue (revision_id, status, reason)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (revision_id) DO UPDATE SET
		     status = EXCLUDED.status,
		     reason = EXCLUDED.reason,
		     updated_at = NOW(),
		     completed_at = NULL,
		     last_error = NULL`).
			WithArgs(revID, TestRevisionMalwareSummaryStatusPending, TestRevisionMalwareSummaryReasonIngest).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectExec(mock, `UPDATE tests SET updated_at = NOW() WHERE id = $1`).
			WithArgs(testID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		revision, err := store.AddRevision(testID, RevisionInput{
			SbomSha256:              "sha",
			SbomProducer:            "syft",
			Tags:                    []string{"v1"},
			MetadataJSON:            []byte(`{"a":"b"}`),
			ComponentsImportedCount: 2,
		})
		if err != nil || revision.ID != revID {
			t.Fatalf("expected revision success")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestListRevisionsAndGetRevision(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	testID := uuid.New()
	existsTest := `SELECT EXISTS(SELECT 1 FROM tests WHERE id = $1)`
	listRevisions := `SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at
		 FROM test_revisions
		 WHERE test_id = $1
		 ORDER BY created_at`
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	if _, err := store.ListRevisions(testID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listRevisions).
		WithArgs(testID).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListRevisions(testID); err == nil {
		t.Fatalf("expected list error")
	}
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listRevisions).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow("bad", testID, "sha", "type", []byte(`[]`), nil, nil, 0, true, time.Now(), time.Now()))
	if _, err := store.ListRevisions(testID); err == nil {
		t.Fatalf("expected scan error")
	}
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listRevisions).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(uuid.New(), testID, "sha", "type", []byte(`{`), nil, nil, 0, true, time.Now(), time.Now()))
	if _, err := store.ListRevisions(testID); err == nil {
		t.Fatalf("expected tags unmarshal error")
	}
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listRevisions).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(uuid.New(), testID, "sha", "type", []byte(`[]`), nil, nil, 0, true, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListRevisions(testID); err == nil {
		t.Fatalf("expected rows error")
	}
	revID := uuid.New()
	now := time.Now()
	expectQuery(mock, existsTest).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	expectQuery(mock, listRevisions).
		WithArgs(testID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(revID, testID, "sha", "type", []byte(`["v1"]`), []byte(`{"a":"b"}`), nil, 1, true, now, now))
	revisions, err := store.ListRevisions(testID)
	if err != nil || len(revisions) != 1 {
		t.Fatalf("expected revisions list")
	}
	getRevision := `SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at
		 FROM test_revisions
		 WHERE id = $1`
	missingRevision := uuid.New()
	expectQuery(mock, getRevision).
		WithArgs(missingRevision).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}))
	if _, err := store.GetRevision(missingRevision); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, getRevision).
		WithArgs(revID).
		WillReturnError(errors.New("boom"))
	if _, err := store.GetRevision(revID); err == nil {
		t.Fatalf("expected get error")
	}
	expectQuery(mock, getRevision).
		WithArgs(revID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(revID, testID, "sha", "type", []byte(`{`), nil, nil, 0, true, now, now))
	if _, err := store.GetRevision(revID); err == nil {
		t.Fatalf("expected tag unmarshal error")
	}
	expectQuery(mock, getRevision).
		WithArgs(revID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(revID, testID, "sha", "type", []byte(`[]`), nil, nil, 0, true, now, now))
	if revision, err := store.GetRevision(revID); err != nil || revision.ID != revID {
		t.Fatalf("expected get revision")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestListAllRevisions(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	listRevisions := `SELECT id, test_id, sbom_sha256, sbom_producer, tags, metadata_json, sbom_metadata_json, components_count, is_active, last_modified_at, created_at
		 FROM test_revisions`
	expectQuery(mock, listRevisions).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListAllRevisions(); err == nil {
		t.Fatalf("expected list error")
	}
	expectQuery(mock, listRevisions).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow("bad", uuid.New(), "sha", "type", []byte(`[]`), nil, nil, 0, true, time.Now(), time.Now()))
	if _, err := store.ListAllRevisions(); err == nil {
		t.Fatalf("expected scan error")
	}
	expectQuery(mock, listRevisions).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(uuid.New(), uuid.New(), "sha", "type", []byte(`{`), nil, nil, 0, true, time.Now(), time.Now()))
	if _, err := store.ListAllRevisions(); err == nil {
		t.Fatalf("expected tags error")
	}
	expectQuery(mock, listRevisions).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(uuid.New(), uuid.New(), "sha", "type", []byte(`[]`), nil, nil, 0, true, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListAllRevisions(); err == nil {
		t.Fatalf("expected rows error")
	}
	revID := uuid.New()
	testID := uuid.New()
	now := time.Now()
	expectQuery(mock, listRevisions).
		WillReturnRows(sqlmock.NewRows([]string{"id", "test_id", "sbom_sha256", "sbom_producer", "tags", "metadata_json", "sbom_metadata_json", "components_count", "is_active", "last_modified_at", "created_at"}).
			AddRow(revID, testID, "sha", "type", []byte(`["v1"]`), []byte(`{"a":"b"}`), nil, 1, true, now, now))
	revisions, err := store.ListAllRevisions()
	if err != nil || len(revisions) != 1 {
		t.Fatalf("expected revisions list")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestDeleteRevision(t *testing.T) {
	selectRevision := `SELECT test_id, sbom_sha256, is_active
		 FROM test_revisions
		 WHERE id = $1`
	deleteRevision := `DELETE FROM test_revisions WHERE id = $1`
	selectNext := `SELECT id FROM test_revisions
			 WHERE test_id = $1
			 ORDER BY created_at DESC
			 LIMIT 1`
	updateNext := `UPDATE test_revisions
				 SET is_active = TRUE, last_modified_at = NOW()
				 WHERE id = $1`
	countRemaining := `SELECT COUNT(1) FROM test_revisions WHERE sbom_sha256 = $1`
	selectStorage := `SELECT storage_path FROM sbom_objects WHERE sha256 = $1`
	deleteSbom := `DELETE FROM sbom_objects WHERE sha256 = $1`
	t.Run("begin error", func(t *testing.T) {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		store, err := NewPostgresStore(db, t.TempDir())
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		mock.ExpectBegin().WillReturnError(errors.New("boom"))
		if err := store.DeleteRevision(uuid.New()); err == nil {
			t.Fatalf("expected begin error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("select error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected select error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("delete error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected delete error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("next update error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		nextID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", true))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, selectNext).
			WithArgs(testID).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(nextID))
		expectExec(mock, updateNext).
			WithArgs(nextID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected update error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("next select error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", true))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, selectNext).
			WithArgs(testID).
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected next select error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("count error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected count error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("storage select error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		expectQuery(mock, selectStorage).
			WithArgs("sha").
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected storage error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("delete sbom error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		expectQuery(mock, selectStorage).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"storage_path"}).AddRow("path"))
		expectExec(mock, deleteSbom).
			WithArgs("sha").
			WillReturnError(errors.New("boom"))
		mock.ExpectRollback()
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected delete sbom error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("commit error", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectCommit().WillReturnError(errors.New("boom"))
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected commit error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("remove error", func(t *testing.T) {
		dir := t.TempDir()
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("sqlmock: %v", err)
		}
		defer db.Close()
		store, err := NewPostgresStore(db, dir)
		if err != nil {
			t.Fatalf("store: %v", err)
		}
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		expectQuery(mock, selectStorage).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"storage_path"}).AddRow("sboms"))
		expectExec(mock, deleteSbom).
			WithArgs("sha").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		path := filepath.Join(dir, "sboms")
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(path, "file"), []byte("data"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
		if err := store.DeleteRevision(revID); err == nil {
			t.Fatalf("expected remove error")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("success remaining>0", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
		mock.ExpectCommit()
		if err := store.DeleteRevision(revID); err != nil {
			t.Fatalf("expected delete success")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("success remove missing file", func(t *testing.T) {
		store, mock := newMockStore(t)
		defer store.Close()
		revID := uuid.New()
		testID := uuid.New()
		mock.ExpectBegin()
		expectQuery(mock, selectRevision).
			WithArgs(revID).
			WillReturnRows(sqlmock.NewRows([]string{"test_id", "sbom_sha256", "is_active"}).
				AddRow(testID, "sha", false))
		expectExec(mock, deleteRevision).
			WithArgs(revID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectQuery(mock, countRemaining).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
		expectQuery(mock, selectStorage).
			WithArgs("sha").
			WillReturnRows(sqlmock.NewRows([]string{"storage_path"}).AddRow("missing.txt"))
		expectExec(mock, deleteSbom).
			WithArgs("sha").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if err := store.DeleteRevision(revID); err != nil {
			t.Fatalf("expected delete success")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestLoadSbomMeta(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	query := `SELECT sha256, storage_path, content_type, is_gzip, format, created_at
		 FROM sbom_objects
		 WHERE sha256 = $1`
	expectQuery(mock, query).
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	if _, err := store.loadSbomMeta("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, query).
		WithArgs("err").
		WillReturnError(errors.New("boom"))
	if _, err := store.loadSbomMeta("err"); err == nil {
		t.Fatalf("expected query error")
	}
	now := time.Now()
	expectQuery(mock, query).
		WithArgs("sha").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}).
			AddRow("sha", "path", " application/json ", true, " cyclonedx ", now))
	meta, err := store.loadSbomMeta("sha")
	if err != nil {
		t.Fatalf("expected meta")
	}
	if meta.StoragePath != "path" || meta.ContentType != "application/json" || meta.Format != "cyclonedx" || !meta.IsGzip {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestCreateIngestJob(t *testing.T) {
	t.Run("invalid payload", func(t *testing.T) {
		store, _ := newMockStore(t)
		if _, err := store.CreateIngestJob(IngestRequest{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected invalid payload")
		}
	})
	t.Run("marshal error", func(t *testing.T) {
		store, _ := newMockStore(t)
		origMarshal := marshalJSON
		marshalJSON = func(any) ([]byte, error) {
			return nil, errors.New("marshal boom")
		}
		defer func() { marshalJSON = origMarshal }()
		productID := uuid.New()
		scopeID := uuid.New()
		testID := uuid.New()
		if _, err := store.CreateIngestJob(IngestRequest{
			ProductID:    &productID,
			ScopeID:      &scopeID,
			TestID:       &testID,
			SbomSha256:   "sha",
			SbomStandard: "cyclonedx",
		}); err == nil {
			t.Fatalf("expected marshal error")
		}
	})
	t.Run("success", func(t *testing.T) {
		store, mock := newMockStore(t)
		productID := uuid.New()
		scopeID := uuid.New()
		testID := uuid.New()
		now := time.Now()
		tagsJSON, err := json.Marshal([]string{"alpha", "beta"})
		if err != nil {
			t.Fatalf("marshal tags: %v", err)
		}
		query := `INSERT INTO ingest_queue (
			 product_id, scope_id, test_id,
			 sbom_sha256, sbom_standard, sbom_spec_version, sbom_producer,
			 tags, metadata_json, content_type, is_gzip, components_count, processing_stage, status
		 )
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		 RETURNING id, status, processing_stage, error_message, created_at, updated_at, completed_at`
		expectQuery(mock, query).
			WithArgs(
				&productID,
				&scopeID,
				&testID,
				"sha",
				"cyclonedx",
				"1.6",
				"syft",
				tagsJSON,
				json.RawMessage(`{"owner":"team"}`),
				"application/json",
				true,
				3,
				IngestStageReceived,
				IngestStatusPending,
			).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "status", "processing_stage", "error_message", "created_at", "updated_at", "completed_at",
			}).AddRow(uuid.New(), IngestStatusPending, IngestStageReceived, "", now, now, nil))
		input := IngestRequest{
			ProductID:       &productID,
			ScopeID:         &scopeID,
			TestID:          &testID,
			SbomSha256:      " sha ",
			SbomStandard:    " CycloneDX ",
			SbomSpecVersion: " 1.6 ",
			SbomProducer:    " Syft ",
			Tags:            []string{" alpha ", "", "beta"},
			MetadataJSON:    json.RawMessage(`{"owner":"team"}`),
			ContentType:     " application/json ",
			IsGzip:          true,
			ComponentsCount: 3,
		}
		job, err := store.CreateIngestJob(input)
		if err != nil {
			t.Fatalf("create ingest job: %v", err)
		}
		if job.Status != IngestStatusPending || job.SbomSha256 != "sha" {
			t.Fatalf("unexpected job fields")
		}
		if job.ProcessingStage != IngestStageReceived {
			t.Fatalf("expected received stage")
		}
		if len(job.Tags) != 2 || job.Tags[0] != "alpha" || job.Tags[1] != "beta" {
			t.Fatalf("expected trimmed tags")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestUpdateIngestJobStatus(t *testing.T) {
	t.Run("invalid status", func(t *testing.T) {
		store, _ := newMockStore(t)
		if err := store.UpdateIngestJobStatus(uuid.New(), "bad", ""); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected invalid payload")
		}
	})
	t.Run("not found", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT status FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnError(sql.ErrNoRows)
		if err := store.UpdateIngestJobStatus(jobID, IngestStatusProcessing, ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT status FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(IngestStatusProcessing))
		query := `UPDATE ingest_queue
		 SET status = $1,
		     error_message = NULLIF($2, ''),
		     updated_at = NOW(),
		     completed_at = CASE WHEN $1 IN ('COMPLETED', 'FAILED') THEN NOW() ELSE NULL END
		 WHERE id = $3`
		expectExec(mock, query).
			WithArgs(IngestStatusCompleted, "error", jobID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := store.UpdateIngestJobStatus(jobID, " completed ", " error "); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("invalid transition", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT status FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnRows(sqlmock.NewRows([]string{"status"}).AddRow(IngestStatusCompleted))
		if err := store.UpdateIngestJobStatus(jobID, IngestStatusProcessing, ""); !errors.Is(err, ErrInvalidStateTransition) {
			t.Fatalf("expected invalid transition")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestUpdateIngestJobStage(t *testing.T) {
	t.Run("invalid stage", func(t *testing.T) {
		store, _ := newMockStore(t)
		if err := store.UpdateIngestJobStage(uuid.New(), "bad", ""); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected invalid payload")
		}
	})
	t.Run("not found", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT processing_stage FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnError(sql.ErrNoRows)
		if err := store.UpdateIngestJobStage(jobID, IngestStageValidating, ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected not found")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("invalid transition", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT processing_stage FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnRows(sqlmock.NewRows([]string{"processing_stage"}).AddRow(IngestStageCompleted))
		if err := store.UpdateIngestJobStage(jobID, IngestStageValidating, ""); !errors.Is(err, ErrInvalidStateTransition) {
			t.Fatalf("expected invalid transition")
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
	t.Run("success", func(t *testing.T) {
		store, mock := newMockStore(t)
		jobID := uuid.New()
		expectQuery(mock, `SELECT processing_stage FROM ingest_queue WHERE id = $1`).
			WithArgs(jobID).
			WillReturnRows(sqlmock.NewRows([]string{"processing_stage"}).AddRow(IngestStageValidating))
		query := `UPDATE ingest_queue
		 SET processing_stage = $1, error_message = $2, updated_at = NOW()
		 WHERE id = $3`
		expectExec(mock, query).
			WithArgs(IngestStageParsing, "error", jobID).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := store.UpdateIngestJobStage(jobID, " parsing ", " error "); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("expectations: %v", err)
		}
	})
}
func TestStoreSbom(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	if _, err := store.StoreSbom("", []byte("x"), "fmt", "type", false); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected invalid payload")
	}
	query := `SELECT sha256, storage_path, content_type, is_gzip, format, created_at
		 FROM sbom_objects
		 WHERE sha256 = $1`
	expectQuery(mock, query).
		WithArgs("exists").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}).
			AddRow("exists", "path", "application/json", false, "cyclonedx", time.Now()))
	obj, err := store.StoreSbom("exists", []byte("data"), "cyclonedx", "application/json", false)
	if err != nil || obj.SHA != "exists" || len(obj.Bytes) == 0 {
		t.Fatalf("expected existing sbom")
	}
	expectQuery(mock, query).
		WithArgs("error").
		WillReturnError(errors.New("boom"))
	if _, err := store.StoreSbom("error", []byte("data"), "fmt", "type", false); err == nil {
		t.Fatalf("expected load error")
	}
	expectQuery(mock, query).
		WithArgs("abc").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	if _, err := store.StoreSbom("abc", []byte("data"), "fmt", "type", false); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected short sha error")
	}
	tempFile := filepath.Join(t.TempDir(), "rootfile")
	if err := os.WriteFile(tempFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	store.storageRoot = tempFile
	expectQuery(mock, query).
		WithArgs("abcd").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	if _, err := store.StoreSbom("abcd", []byte("data"), "fmt", "type", false); err == nil {
		t.Fatalf("expected mkdir error")
	}
	store.storageRoot = t.TempDir()
	expectQuery(mock, query).
		WithArgs("abce").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	origOpenFile := openFile
	openFile = func(string, int, os.FileMode) (fileWriter, error) {
		return failingWriter{}, nil
	}
	if _, err := store.StoreSbom("abce", []byte("data"), "fmt", "type", false); err == nil {
		t.Fatalf("expected write error")
	}
	openFile = origOpenFile
	insertSbom := `INSERT INTO sbom_objects (sha256, storage_path, size_bytes, format, content_type, is_gzip)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (sha256) DO NOTHING`
	expectQuery(mock, query).
		WithArgs("abcf").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	expectExec(mock, insertSbom).
		WithArgs("abcf", filepath.Join("ab", "cf", "abcf"), len([]byte("data")), "fmt", "type", false).
		WillReturnError(errors.New("boom"))
	if _, err := store.StoreSbom("abcf", []byte("data"), "fmt", "type", false); err == nil {
		t.Fatalf("expected insert error")
	}
	expectQuery(mock, query).
		WithArgs("abcg").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	expectExec(mock, insertSbom).
		WithArgs("abcg", filepath.Join("ab", "cg", "abcg"), len([]byte("data")), "unknown", "", true).
		WillReturnResult(sqlmock.NewResult(0, 1))
	obj, err = store.StoreSbom("abcg", []byte("data"), "", "", true)
	if err != nil || obj.Format != "unknown" || obj.IsGzip != true {
		t.Fatalf("expected store success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestGetSbomBySHA(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	query := `SELECT sha256, storage_path, content_type, is_gzip, format, created_at
		 FROM sbom_objects
		 WHERE sha256 = $1`
	expectQuery(mock, query).
		WithArgs("missing").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}))
	if _, err := store.GetSbomBySHA("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectQuery(mock, query).
		WithArgs("sha").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}).
			AddRow("sha", "missing.txt", "", false, "fmt", time.Now()))
	if _, err := store.GetSbomBySHA("sha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected file not found")
	}
	path := filepath.Join(store.storageRoot, "noaccess.txt")
	if err := os.WriteFile(path, []byte("data"), 0o000); err != nil {
		t.Fatalf("write file: %v", err)
	}
	expectQuery(mock, query).
		WithArgs("noaccess").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}).
			AddRow("noaccess", "noaccess.txt", "", false, "fmt", time.Now()))
	if _, err := store.GetSbomBySHA("noaccess"); err == nil {
		t.Fatalf("expected read error")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	goodPath := filepath.Join(store.storageRoot, "good.txt")
	if err := os.WriteFile(goodPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	expectQuery(mock, query).
		WithArgs("good").
		WillReturnRows(sqlmock.NewRows([]string{"sha256", "storage_path", "content_type", "is_gzip", "format", "created_at"}).
			AddRow("good", "good.txt", "application/json", false, "fmt", time.Now()))
	obj, err := store.GetSbomBySHA("good")
	if err != nil || string(obj.Bytes) != "payload" {
		t.Fatalf("expected sbom payload")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
func TestListAllScopesTestsUsers(t *testing.T) {
	store, mock := newMockStore(t)
	defer store.Close()
	listScopes := `SELECT id, product_id, name, description, archived_at, created_at, updated_at
		 FROM scopes
		 WHERE archived_at IS NULL`
	expectQuery(mock, listScopes).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListAllScopes(); err == nil {
		t.Fatalf("expected list scopes error")
	}
	expectQuery(mock, listScopes).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow("bad", uuid.New(), "Core", "", nil, time.Now(), time.Now()))
	if _, err := store.ListAllScopes(); err == nil {
		t.Fatalf("expected scope scan error")
	}
	expectQuery(mock, listScopes).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), uuid.New(), "Core", "", nil, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListAllScopes(); err == nil {
		t.Fatalf("expected scope rows error")
	}
	expectQuery(mock, listScopes).
		WillReturnRows(sqlmock.NewRows([]string{"id", "product_id", "name", "description", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), uuid.New(), "Core", "", nil, time.Now(), time.Now()))
	scopes, err := store.ListAllScopes()
	if err != nil || len(scopes) != 1 {
		t.Fatalf("expected scopes list")
	}
	listTests := `SELECT id, scope_id, name, sbom_standard, sbom_spec_version, is_public, public_token, archived_at, created_at, updated_at
		 FROM tests
		 WHERE archived_at IS NULL`
	expectQuery(mock, listTests).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListAllTests(); err == nil {
		t.Fatalf("expected list tests error")
	}
	expectQuery(mock, listTests).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow("bad", uuid.New(), "Gateway", "cyclonedx", "1.6", false, "", nil, time.Now(), time.Now()))
	if _, err := store.ListAllTests(); err == nil {
		t.Fatalf("expected tests scan error")
	}
	expectQuery(mock, listTests).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), uuid.New(), "Gateway", "cyclonedx", "1.6", false, "", nil, time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListAllTests(); err == nil {
		t.Fatalf("expected tests rows error")
	}
	expectQuery(mock, listTests).
		WillReturnRows(sqlmock.NewRows([]string{"id", "scope_id", "name", "sbom_standard", "sbom_spec_version", "is_public", "public_token", "archived_at", "created_at", "updated_at"}).
			AddRow(uuid.New(), uuid.New(), "Gateway", "cyclonedx", "1.6", false, "", nil, time.Now(), time.Now()))
	tests, err := store.ListAllTests()
	if err != nil || len(tests) != 1 {
		t.Fatalf("expected tests list")
	}
	listUsers := `SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at
		 FROM users
		 ORDER BY email`
	expectQuery(mock, listUsers).
		WillReturnError(errors.New("boom"))
	if _, err := store.ListUsers(); err == nil {
		t.Fatalf("expected list users error")
	}
	expectQuery(mock, listUsers).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow("bad", "user@example.com", "ADMIN", "USER", "user", "User", time.Now(), time.Now()))
	if _, err := store.ListUsers(); err == nil {
		t.Fatalf("expected users scan error")
	}
	expectQuery(mock, listUsers).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(uuid.New(), "user@example.com", "ADMIN", "USER", "user", "User", time.Now(), time.Now()).
			RowError(0, errors.New("row error")))
	if _, err := store.ListUsers(); err == nil {
		t.Fatalf("expected users rows error")
	}
	expectQuery(mock, listUsers).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "account_type", "nickname", "full_name", "created_at", "updated_at"}).
			AddRow(uuid.New(), "user@example.com", "ADMIN", "USER", "user", "User", time.Now(), time.Now()))
	users, err := store.ListUsers()
	if err != nil || len(users) != 1 {
		t.Fatalf("expected users list")
	}
	deleteUser := `DELETE FROM users WHERE id = $1`
	userID := uuid.New()
	expectExec(mock, deleteUser).
		WithArgs(userID).
		WillReturnError(errors.New("boom"))
	if err := store.DeleteUser(userID); err == nil {
		t.Fatalf("expected delete user error")
	}
	expectExec(mock, deleteUser).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewErrorResult(errors.New("rows error")))
	if err := store.DeleteUser(userID); err == nil {
		t.Fatalf("expected rows affected error")
	}
	expectExec(mock, deleteUser).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	if err := store.DeleteUser(userID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found")
	}
	expectExec(mock, deleteUser).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	if err := store.DeleteUser(userID); err != nil {
		t.Fatalf("expected delete user success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
