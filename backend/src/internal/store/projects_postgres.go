package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"backend/internal/models"

	"github.com/google/uuid"
)

const defaultProjectName = "Default Project"

func scanProject(row *sql.Row) (*models.Project, error) {
	var project models.Project
	if err := row.Scan(
		&project.ID,
		&project.Name,
		&project.Description,
		&project.ArchivedAt,
		&project.CreatedBy,
		&project.CreatedAt,
		&project.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &project, nil
}

func normalizeProjectMemberAssignments(members []ProjectMemberAssignment) ([]ProjectMemberAssignment, error) {
	out := make([]ProjectMemberAssignment, 0, len(members))
	seen := make(map[uuid.UUID]struct{}, len(members))
	for _, member := range members {
		if member.UserID == uuid.Nil {
			return nil, ErrInvalidPayload
		}
		role := NormalizeProjectRole(member.ProjectRole)
		if !IsValidProjectRole(role) {
			return nil, ErrInvalidPayload
		}
		if _, exists := seen[member.UserID]; exists {
			return nil, ErrInvalidPayload
		}
		seen[member.UserID] = struct{}{}
		out = append(out, ProjectMemberAssignment{
			UserID:      member.UserID,
			ProjectRole: role,
		})
	}
	return out, nil
}

func (s *PostgresStore) defaultProjectID(ctx context.Context) (uuid.UUID, error) {
	var projectID uuid.UUID
	err := s.db.QueryRowContext(ctx,
		`SELECT id
		 FROM projects
		 WHERE LOWER(name) = LOWER($1)
		 LIMIT 1`,
		defaultProjectName,
	).Scan(&projectID)
	if err == nil {
		return projectID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}

	err = s.db.QueryRowContext(ctx,
		`INSERT INTO projects (name, description)
		 VALUES ($1, $2)
		 RETURNING id`,
		defaultProjectName,
		"Default workspace.",
	).Scan(&projectID)
	if err != nil {
		return uuid.Nil, err
	}
	return projectID, nil
}

func (s *PostgresStore) ensureProjectExists(ctx context.Context, projectID uuid.UUID) error {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM projects
		   WHERE id = $1
		 )`,
		projectID,
	).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) EnsureUserSettings(userID uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	defaultProjectID, err := s.defaultProjectID(ctx)
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO user_settings (user_id, selected_project_id, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (user_id) DO NOTHING`,
		userID,
		defaultProjectID,
	); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) ListProjectsForUser(userID uuid.UUID, includeAll bool) ([]models.Project, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var (
		rows *sql.Rows
		err  error
	)
	if includeAll {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, description, archived_at, created_by, created_at, updated_at
			 FROM projects
			 WHERE archived_at IS NULL
			 ORDER BY name`)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT p.id, p.name, p.description, p.archived_at, p.created_by, p.created_at, p.updated_at
			 FROM projects p
			 JOIN project_memberships pm ON pm.project_id = p.id
			 WHERE pm.user_id = $1
			   AND p.archived_at IS NULL
			 ORDER BY p.name`,
			userID,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.Project, 0)
	for rows.Next() {
		var item models.Project
		if err := rows.Scan(
			&item.ID,
			&item.Name,
			&item.Description,
			&item.ArchivedAt,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) CreateProject(name, description string, createdBy *uuid.UUID) (*models.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO projects (name, description, created_by)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (LOWER(name)) DO NOTHING
		 RETURNING id, name, description, archived_at, created_by, created_at, updated_at`,
		name,
		strings.TrimSpace(description),
		createdBy,
	)
	project, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (s *PostgresStore) UpdateProject(id uuid.UUID, name, description string) (*models.Project, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidPayload
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`UPDATE projects
		 SET name = $2,
		     description = $3,
		     updated_at = NOW()
		 WHERE id = $1
		 RETURNING id, name, description, archived_at, created_by, created_at, updated_at`,
		id,
		name,
		strings.TrimSpace(description),
	)
	project, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if isUniqueViolation(err) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (s *PostgresStore) GetProject(id uuid.UUID) (*models.Project, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, archived_at, created_by, created_at, updated_at
		 FROM projects
		 WHERE id = $1`,
		id,
	)
	project, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (s *PostgresStore) DeleteProject(id uuid.UUID) (*models.Project, []models.Product, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	projectRow := tx.QueryRowContext(ctx,
		`SELECT id, name, description, archived_at, created_by, created_at, updated_at
		 FROM projects
		 WHERE id = $1
		 FOR UPDATE`,
		id,
	)
	var project models.Project
	if err := projectRow.Scan(
		&project.ID,
		&project.Name,
		&project.Description,
		&project.ArchivedAt,
		&project.CreatedBy,
		&project.CreatedAt,
		&project.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}

	productsRows, err := tx.QueryContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE project_id = $1
		 ORDER BY name`,
		id,
	)
	if err != nil {
		return nil, nil, err
	}
	products := make([]models.Product, 0)
	for productsRows.Next() {
		var product models.Product
		if err := productsRows.Scan(
			&product.ID,
			&product.ProjectID,
			&product.Name,
			&product.Description,
			&product.ArchivedAt,
			&product.CreatedAt,
			&product.UpdatedAt,
		); err != nil {
			productsRows.Close()
			return nil, nil, err
		}
		products = append(products, product)
	}
	if err := productsRows.Err(); err != nil {
		productsRows.Close()
		return nil, nil, err
	}
	productsRows.Close()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM projects WHERE id = $1`,
		id,
	); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return &project, products, nil
}

func (s *PostgresStore) ListProjectMembers(projectID uuid.UUID) ([]models.ProjectMember, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.role, u.account_type, u.nickname, u.full_name, pm.project_role, u.created_at, u.updated_at
		 FROM users u
		 JOIN project_memberships pm ON pm.user_id = u.id
		 WHERE pm.project_id = $1
		 ORDER BY u.email`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]models.ProjectMember, 0)
	for rows.Next() {
		var user models.ProjectMember
		var fullName sql.NullString
		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Role,
			&user.AccountType,
			&user.Nickname,
			&fullName,
			&user.ProjectRole,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, err
		}
		user.FullName = nullStringToString(fullName)
		user.ProjectRole = NormalizeProjectRole(user.ProjectRole)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *PostgresStore) GetProjectRole(userID, projectID uuid.UUID) (string, error) {
	if userID == uuid.Nil || projectID == uuid.Nil {
		return "", ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT project_role
		 FROM project_memberships
		 WHERE project_id = $1
		   AND user_id = $2`,
		projectID,
		userID,
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return NormalizeProjectRole(role), nil
}

func (s *PostgresStore) ReplaceProjectMembers(projectID uuid.UUID, members []ProjectMemberAssignment, createdBy *uuid.UUID) error {
	if projectID == uuid.Nil {
		return ErrInvalidPayload
	}

	normalizedMembers, err := normalizeProjectMemberAssignments(members)
	if err != nil {
		return err
	}
	if len(normalizedMembers) == 0 {
		return ErrInvalidStateTransition
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	memberIDs := make([]uuid.UUID, 0, len(normalizedMembers))
	adminCount := 0
	for _, member := range normalizedMembers {
		memberIDs = append(memberIDs, member.UserID)
		if NormalizeProjectRole(member.ProjectRole) == ProjectRoleAdmin {
			adminCount++
		}
	}
	if adminCount == 0 {
		return ErrInvalidStateTransition
	}

	var usersFound int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*)
		 FROM users
		 WHERE id = ANY($1::uuid[])`,
		memberIDs,
	).Scan(&usersFound); err != nil {
		return err
	}
	if usersFound != len(memberIDs) {
		return ErrNotFound
	}

	var orphanedCreators int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT p.created_by)
		 FROM products p
		 WHERE p.project_id = $1
		   AND p.created_by IS NOT NULL
		   AND NOT (p.created_by = ANY($2::uuid[]))`,
		projectID,
		memberIDs,
	).Scan(&orphanedCreators); err != nil {
		return err
	}
	if orphanedCreators > 0 {
		return ErrInvalidStateTransition
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM project_memberships
		 WHERE project_id = $1`,
		projectID,
	); err != nil {
		return err
	}

	for _, member := range normalizedMembers {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO project_memberships (project_id, user_id, project_role, created_by)
			 VALUES ($1, $2, $3, $4)`,
			projectID,
			member.UserID,
			member.ProjectRole,
			createdBy,
		); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) GetSelectedProjectID(userID uuid.UUID) (*uuid.UUID, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	var selected uuid.NullUUID
	err := s.db.QueryRowContext(ctx,
		`SELECT selected_project_id
		 FROM user_settings
		 WHERE user_id = $1`,
		userID,
	).Scan(&selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !selected.Valid {
		return nil, nil
	}
	out := selected.UUID
	return &out, nil
}

func (s *PostgresStore) SetSelectedProjectID(userID, projectID uuid.UUID) error {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO user_settings (user_id, selected_project_id, updated_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (user_id) DO UPDATE
		 SET selected_project_id = EXCLUDED.selected_project_id,
		     updated_at = NOW()`,
		userID,
		projectID,
	); err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) UserHasProjectAccess(userID, projectID uuid.UUID, includeAll bool) (bool, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if includeAll {
		var exists bool
		if err := s.db.QueryRowContext(ctx,
			`SELECT EXISTS(
			   SELECT 1
			   FROM projects
			   WHERE id = $1
			     AND archived_at IS NULL
			 )`,
			projectID,
		).Scan(&exists); err != nil {
			return false, err
		}
		return exists, nil
	}

	var hasAccess bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM projects p
		   JOIN project_memberships pm ON pm.project_id = p.id
		   WHERE p.id = $1
		     AND pm.user_id = $2
		     AND p.archived_at IS NULL
		 )`,
		projectID,
		userID,
	).Scan(&hasAccess); err != nil {
		return false, err
	}
	return hasAccess, nil
}

func (s *PostgresStore) EnsureProductInProject(projectID uuid.UUID, name, description string) (*models.Product, bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, false, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, false, err
	}

	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE project_id = $1
		   AND LOWER(name) = LOWER($2)
		 LIMIT 1`,
		projectID,
		name,
	)
	product, err := scanProduct(row)
	if err == nil {
		return product, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, err
	}

	created, err := s.CreateProductInProject(projectID, name, description)
	if err == ErrAlreadyExists {
		row = s.db.QueryRowContext(ctx,
			`SELECT id, project_id, name, description, archived_at, created_at, updated_at
			 FROM products
			 WHERE project_id = $1
			   AND LOWER(name) = LOWER($2)
			 LIMIT 1`,
			projectID,
			name,
		)
		product, err = scanProduct(row)
		if err != nil {
			return nil, false, err
		}
		return product, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

func (s *PostgresStore) CreateProductInProject(projectID uuid.UUID, name, description string) (*models.Product, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidPayload
	}
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	row := s.db.QueryRowContext(ctx,
		`INSERT INTO products (project_id, name, description)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (project_id, LOWER(name)) DO NOTHING
		 RETURNING id, project_id, name, description, archived_at, created_at, updated_at`,
		projectID,
		name,
		strings.TrimSpace(description),
	)
	product, err := scanProduct(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		return nil, err
	}
	return product, nil
}

func (s *PostgresStore) GetProductInProject(projectID, productID uuid.UUID) (*models.Product, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE id = $1
		   AND project_id = $2`,
		productID,
		projectID,
	)
	product, err := scanProduct(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return product, nil
}

func (s *PostgresStore) ListProductsByProject(projectID uuid.UUID) ([]models.Product, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, description, archived_at, created_at, updated_at
		 FROM products
		 WHERE project_id = $1
		   AND archived_at IS NULL
		 ORDER BY name`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.Product, 0)
	for rows.Next() {
		var item models.Product
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.Name,
			&item.Description,
			&item.ArchivedAt,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) GetScopeInProject(projectID, scopeID uuid.UUID) (*models.Scope, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.product_id, s.name, s.description, s.archived_at, s.created_at, s.updated_at
		 FROM scopes s
		 JOIN products p ON p.id = s.product_id
		 WHERE s.id = $1
		   AND p.project_id = $2`,
		scopeID,
		projectID,
	)
	scope, err := scanScope(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return scope, nil
}

func (s *PostgresStore) GetTestInProject(projectID, testID uuid.UUID) (*models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.scope_id, t.name, t.sbom_standard, t.sbom_spec_version, t.is_public, t.public_token, t.archived_at, t.created_at, t.updated_at
		 FROM tests t
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 WHERE t.id = $1
		   AND p.project_id = $2`,
		testID,
		projectID,
	)
	test, err := scanTest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return test, nil
}

func (s *PostgresStore) GetRevisionInProject(projectID, revisionID uuid.UUID) (*models.TestRevision, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	row := s.db.QueryRowContext(ctx,
		`SELECT tr.id, tr.test_id, tr.sbom_sha256, tr.sbom_producer, tr.tags, tr.metadata_json, tr.sbom_metadata_json,
		        tr.components_count, tr.is_active, tr.last_modified_at, tr.created_at
		 FROM test_revisions tr
		 JOIN tests t ON t.id = tr.test_id
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 WHERE tr.id = $1
		   AND p.project_id = $2`,
		revisionID,
		projectID,
	)
	revision, err := scanRevision(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return revision, nil
}

func (s *PostgresStore) DeleteRevisionInProject(projectID, revisionID uuid.UUID) error {
	if _, err := s.GetRevisionInProject(projectID, revisionID); err != nil {
		return err
	}
	return s.DeleteRevision(revisionID)
}

func (s *PostgresStore) ListAllScopesByProject(projectID uuid.UUID) ([]models.Scope, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT s.id, s.product_id, s.name, s.description, s.archived_at, s.created_at, s.updated_at
		 FROM scopes s
		 JOIN products p ON p.id = s.product_id
		 WHERE p.project_id = $1
		   AND s.archived_at IS NULL`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.Scope, 0)
	for rows.Next() {
		var item models.Scope
		if err := rows.Scan(
			&item.ID,
			&item.ProductID,
			&item.Name,
			&item.Description,
			&item.ArchivedAt,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) ListAllTestsByProject(projectID uuid.UUID) ([]models.Test, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`SELECT t.id, t.scope_id, t.name, t.sbom_standard, t.sbom_spec_version, t.is_public, t.public_token, t.archived_at, t.created_at, t.updated_at
		 FROM tests t
		 JOIN scopes s ON s.id = t.scope_id
		 JOIN products p ON p.id = s.product_id
		 WHERE p.project_id = $1
		   AND t.archived_at IS NULL`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.Test, 0)
	for rows.Next() {
		var test models.Test
		var publicToken sql.NullString
		if err := rows.Scan(
			&test.ID,
			&test.ScopeID,
			&test.Name,
			&test.SbomStandard,
			&test.SbomSpecVersion,
			&test.IsPublic,
			&publicToken,
			&test.ArchivedAt,
			&test.CreatedAt,
			&test.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if publicToken.Valid {
			test.PublicToken = publicToken.String
		}
		items = append(items, test)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
