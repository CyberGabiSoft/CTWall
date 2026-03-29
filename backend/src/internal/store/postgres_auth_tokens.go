package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func normalizeNicknameFromInput(nickname, fullName, email string) string {
	if cleaned := strings.TrimSpace(nickname); cleaned != "" {
		return cleaned
	}
	if cleaned := strings.TrimSpace(fullName); cleaned != "" {
		return cleaned
	}
	local := strings.TrimSpace(strings.SplitN(strings.TrimSpace(email), "@", 2)[0])
	if local != "" {
		return local
	}
	return "user"
}

func parseUserProfileArgs(email string, profile []string) (nickname string, fullName string, err error) {
	switch len(profile) {
	case 0:
		return "", "", ErrInvalidPayload
	case 1:
		fullName = strings.TrimSpace(profile[0])
		return normalizeNicknameFromInput("", fullName, email), fullName, nil
	case 2:
		nickname = strings.TrimSpace(profile[0])
		fullName = strings.TrimSpace(profile[1])
		nickname = normalizeNicknameFromInput(nickname, fullName, email)
		return nickname, fullName, nil
	default:
		return "", "", fmt.Errorf("%w: invalid user profile args", ErrInvalidPayload)
	}
}

func (s *PostgresStore) GetUserByEmail(email string) (*UserCredentials, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at, password_hash
		 FROM users
		 WHERE LOWER(email) = LOWER($1)
		 LIMIT 1`, email,
	)
	creds, err := scanUserCredentials(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return creds, nil
}

// CreateUser creates a new user with a password hash.
func (s *PostgresStore) CreateUser(email, passwordHash, role, accountType string, profile ...string) (*models.User, error) {
	email = strings.TrimSpace(email)
	passwordHash = strings.TrimSpace(passwordHash)
	role = strings.TrimSpace(role)
	accountType = strings.TrimSpace(accountType)
	if email == "" || passwordHash == "" || role == "" || accountType == "" {
		return nil, ErrInvalidPayload
	}
	nickname, fullName, err := parseUserProfileArgs(email, profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`INSERT INTO users (email, password_hash, role, account_type, nickname, full_name)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT (email) DO NOTHING
		 RETURNING id, email, role, account_type, nickname, full_name, created_at, updated_at`,
		email, passwordHash, role, accountType, nickname, fullName,
	)
	var user models.User
	var createdFullName sql.NullString
	if err := row.Scan(&user.ID, &user.Email, &user.Role, &user.AccountType, &user.Nickname, &createdFullName, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	user.FullName = nullStringToString(createdFullName)

	var defaultProjectID uuid.UUID
	err = tx.QueryRowContext(ctx,
		`SELECT id
		 FROM projects
		 WHERE LOWER(name) = LOWER($1)
		 LIMIT 1`,
		defaultProjectName,
	).Scan(&defaultProjectID)
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx,
			`INSERT INTO projects (name, description)
			 VALUES ($1, $2)
			 RETURNING id`,
			defaultProjectName,
			"Default workspace.",
		).Scan(&defaultProjectID)
	}
	if err != nil {
		return nil, err
	}

	assignDefaultProjectAccess := !strings.EqualFold(user.Role, "NONE")
	if assignDefaultProjectAccess {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO project_memberships (project_id, user_id, project_role, created_by)
			 VALUES ($1, $2,
			         CASE
			           WHEN UPPER($3) = 'ADMIN' THEN 'ADMIN'
			           WHEN UPPER($3) = 'WRITER' THEN 'WRITER'
			           ELSE 'READER'
			         END,
			         NULL)
			 ON CONFLICT (project_id, user_id) DO NOTHING`,
			defaultProjectID,
			user.ID,
			user.Role,
		); err != nil {
			return nil, err
		}
	}
	var selectedProjectID any = defaultProjectID
	if !assignDefaultProjectAccess {
		selectedProjectID = nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_settings (user_id, selected_project_id, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (user_id) DO UPDATE
		 SET selected_project_id = EXCLUDED.selected_project_id,
		     updated_at = NOW()`,
		user.ID,
		selectedProjectID,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates mutable user profile fields managed by admins.
// Email is immutable after user creation.
func (s *PostgresStore) UpdateUser(id uuid.UUID, role, accountType string, profile ...string) (*models.User, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	role = strings.TrimSpace(role)
	accountType = strings.TrimSpace(accountType)
	if role == "" || accountType == "" {
		return nil, ErrInvalidPayload
	}
	nickname, fullName, err := parseUserProfileArgs("", profile)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(nickname) == "" {
		// preserve non-empty invariant at API/store layer before DB check constraint
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	updateQuery := `UPDATE users
		 SET role = $2,
		     account_type = $3,
		     nickname = $4,
		     full_name = $5,
		     updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, email, role, account_type, nickname, full_name, created_at, updated_at`
	if strings.EqualFold(role, "NONE") {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()

		row := tx.QueryRowContext(ctx, updateQuery, id, role, accountType, nickname, fullName)
		user, err := scanUser(row)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM project_memberships WHERE user_id = $1`, id); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE user_settings
			 SET selected_project_id = NULL,
			     updated_at = NOW()
			 WHERE user_id = $1`,
			id,
		); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return user, nil
	}

	row := s.db.QueryRowContext(ctx, updateQuery, id, role, accountType, nickname, fullName)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUserPassword updates the password hash for a user.
func (s *PostgresStore) UpdateUserPassword(userID uuid.UUID, passwordHash string) error {
	if userID == uuid.Nil {
		return ErrInvalidPayload
	}
	passwordHash = strings.TrimSpace(passwordHash)
	if passwordHash == "" {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	result, err := s.db.ExecContext(ctx,
		`UPDATE users
		 SET password_hash = $1, updated_at = NOW()
		 WHERE id = $2`,
		passwordHash, userID,
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

// GetUserByID returns a user by ID.
func (s *PostgresStore) GetUserByID(id uuid.UUID) (*models.User, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, email, role, account_type, nickname, full_name, created_at, updated_at
		 FROM users
		 WHERE id = $1`, id,
	)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// CreateAPIToken creates a new API token for a user.
func (s *PostgresStore) CreateAPIToken(userID uuid.UUID, name, tokenHash string, expiresAt *time.Time) (*APIToken, error) {
	if userID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	name = strings.TrimSpace(name)
	tokenHash = strings.TrimSpace(tokenHash)
	if name == "" || tokenHash == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO api_tokens (user_id, name, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, user_id, name, token_hash, last_used_at, expires_at, created_at`,
		userID, name, tokenHash, expiresAt,
	)
	token, err := scanAPIToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return token, nil
}

// CreateRefreshToken creates a new refresh token for a user.
func (s *PostgresStore) CreateRefreshToken(userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, error) {
	if userID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	tokenHash = strings.TrimSpace(tokenHash)
	userAgent = strings.TrimSpace(userAgent)
	ipAddress = strings.TrimSpace(ipAddress)
	if tokenHash == "" || expiresAt.IsZero() {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`,
		userID, tokenHash, expiresAt.UTC(), userAgent, ipAddress,
	)
	token, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return token, nil
}

// CreateRefreshTokenAndRevokeOthers creates a refresh token and revokes other active tokens for the user.
func (s *PostgresStore) CreateRefreshTokenAndRevokeOthers(userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, error) {
	if userID == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	tokenHash = strings.TrimSpace(tokenHash)
	userAgent = strings.TrimSpace(userAgent)
	ipAddress = strings.TrimSpace(ipAddress)
	if tokenHash == "" || expiresAt.IsZero() {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	row := tx.QueryRowContext(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`,
		userID, tokenHash, expiresAt.UTC(), userAgent, ipAddress,
	)
	token, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE user_id = $1
		   AND id <> $2
		   AND revoked_at IS NULL
		   AND expires_at > NOW()`, userID, token.ID,
	); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return token, nil
}

// RotateRefreshToken invalidates the current refresh token and issues a new one.
func (s *PostgresStore) RotateRefreshToken(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, *models.User, error) {
	currentHash = strings.TrimSpace(currentHash)
	newHash = strings.TrimSpace(newHash)
	userAgent = strings.TrimSpace(userAgent)
	ipAddress = strings.TrimSpace(ipAddress)
	if currentHash == "" || newHash == "" || newExpiresAt.IsZero() {
		return nil, nil, ErrInvalidPayload
	}

	const maxRetries = 3
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		token, user, err := s.rotateRefreshTokenOnce(currentHash, newHash, newExpiresAt, userAgent, ipAddress)
		if err == nil {
			return token, user, nil
		}
		if err == ErrNotFound {
			return nil, nil, err
		}
		if !isSerializationFailure(err) {
			return nil, nil, err
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	return nil, nil, lastErr
}

// RevokeRefreshToken marks a refresh token as revoked.
func (s *PostgresStore) RevokeRefreshToken(tokenHash string) error {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if _, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE token_hash = $1
		   AND revoked_at IS NULL`, tokenHash,
	); err != nil {
		return err
	}
	return nil
}

// RevokeRefreshTokensForUser marks all refresh tokens for a user as revoked.
func (s *PostgresStore) RevokeRefreshTokensForUser(userID uuid.UUID) error {
	if userID == uuid.Nil {
		return ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if _, err := s.db.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = NOW(), last_used_at = NOW()
		 WHERE user_id = $1
		   AND revoked_at IS NULL`, userID,
	); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) rotateRefreshTokenOnce(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, *models.User, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var current RefreshToken
	var user models.User
	var revoked sql.NullTime
	var replaced sql.NullString
	var fullName sql.NullString
	row := tx.QueryRowContext(ctx,
		`SELECT t.id, t.user_id, t.token_hash, t.expires_at, t.revoked_at, t.replaced_by_id, t.created_at, t.last_used_at, t.user_agent, t.ip_address,
		        u.id, u.email, u.role, u.account_type, u.nickname, u.full_name, u.created_at, u.updated_at
		 FROM refresh_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1
		 FOR UPDATE`, currentHash,
	)
	if err := row.Scan(
		&current.ID,
		&current.UserID,
		&current.TokenHash,
		&current.ExpiresAt,
		&revoked,
		&replaced,
		&current.CreatedAt,
		&current.LastUsedAt,
		&current.UserAgent,
		&current.IPAddress,
		&user.ID,
		&user.Email,
		&user.Role,
		&user.AccountType,
		&user.Nickname,
		&fullName,
		&user.CreatedAt,
		&user.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	if revoked.Valid || current.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, ErrNotFound
	}
	user.FullName = nullStringToString(fullName)
	if replaced.Valid {
		return nil, nil, ErrNotFound
	}

	insertRow := tx.QueryRowContext(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, expires_at, revoked_at, replaced_by_id, created_at, last_used_at, user_agent, ip_address`,
		current.UserID, newHash, newExpiresAt.UTC(), userAgent, ipAddress,
	)
	newToken, err := scanRefreshToken(insertRow)
	if err != nil {
		return nil, nil, err
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE refresh_tokens
		 SET revoked_at = NOW(), replaced_by_id = $1, last_used_at = NOW()
		 WHERE id = $2`, newToken.ID, current.ID,
	); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}

	return newToken, &user, nil
}

func isSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "40001" {
		return true
	}
	return false
}

// GetAPITokenByHash returns an API token and its user by hash.
func (s *PostgresStore) GetAPITokenByHash(hash string) (*APIToken, *models.User, error) {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return nil, nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.user_id, t.name, t.token_hash, t.last_used_at, t.expires_at, t.created_at,
		        u.id, u.email, u.role, u.account_type, u.nickname, u.full_name, u.created_at, u.updated_at
		 FROM api_tokens t
		 JOIN users u ON u.id = t.user_id
		 WHERE t.token_hash = $1`, hash,
	)
	token, user, err := scanAPITokenWithUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now().UTC()) {
		return nil, nil, ErrNotFound
	}
	if err := s.UpdateAPITokenLastUsed(token.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	return token, user, nil
}

// UpdateAPITokenLastUsed updates the last_used_at value for a token.
func (s *PostgresStore) UpdateAPITokenLastUsed(id uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	result, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1`, id,
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

// CreateAuditLog inserts an audit log entry.
