package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"backend/internal/models"

	"github.com/google/uuid"
)

func normalizeProductGrantRole(role string) string {
	return strings.ToUpper(strings.TrimSpace(role))
}

func roleRank(role string) int {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case GroupMemberRoleOwner:
		return 3
	case GroupMemberRoleEditor:
		return 2
	case GroupMemberRoleViewer:
		return 1
	default:
		return 0
	}
}

func minRoleByRank(a, b string) string {
	if roleRank(a) <= roleRank(b) {
		return strings.ToUpper(strings.TrimSpace(a))
	}
	return strings.ToUpper(strings.TrimSpace(b))
}

func maxRoleByRank(a, b string) string {
	if roleRank(a) >= roleRank(b) {
		return strings.ToUpper(strings.TrimSpace(a))
	}
	return strings.ToUpper(strings.TrimSpace(b))
}

func scanProductWithOwnership(row *sql.Row) (*models.Product, error) {
	var (
		product      models.Product
		ownerGroupID uuid.NullUUID
		createdBy    uuid.NullUUID
	)
	if err := row.Scan(
		&product.ID,
		&product.ProjectID,
		&product.Name,
		&product.Description,
		&ownerGroupID,
		&createdBy,
		&product.ArchivedAt,
		&product.CreatedAt,
		&product.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if ownerGroupID.Valid {
		id := ownerGroupID.UUID
		product.OwnerGroupID = &id
	}
	if createdBy.Valid {
		id := createdBy.UUID
		product.CreatedBy = &id
	}
	return &product, nil
}

func (s *PostgresStore) ListGroupsByProject(projectID uuid.UUID) ([]models.UserGroup, error) {
	if projectID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project_id, name, description, created_at, created_by
		 FROM user_groups
		 WHERE project_id = $1
		 ORDER BY name, id`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.UserGroup, 0)
	for rows.Next() {
		var (
			item      models.UserGroup
			createdBy uuid.NullUUID
		)
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.Name,
			&item.Description,
			&item.CreatedAt,
			&createdBy,
		); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			id := createdBy.UUID
			item.CreatedBy = &id
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) CreateGroupInProject(projectID uuid.UUID, name, description string, createdBy uuid.UUID) (*models.UserGroup, error) {
	name = strings.TrimSpace(name)
	if projectID == uuid.Nil || createdBy == uuid.Nil || name == "" {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var (
		group        models.UserGroup
		rowCreatedBy uuid.NullUUID
		cleanDesc    = strings.TrimSpace(description)
	)
	row := tx.QueryRowContext(ctx,
		`INSERT INTO user_groups (project_id, name, description, created_by)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, project_id, name, description, created_at, created_by`,
		projectID,
		name,
		cleanDesc,
		createdBy,
	)
	if err := row.Scan(
		&group.ID,
		&group.ProjectID,
		&group.Name,
		&group.Description,
		&group.CreatedAt,
		&rowCreatedBy,
	); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if rowCreatedBy.Valid {
		id := rowCreatedBy.UUID
		group.CreatedBy = &id
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_group_members (group_id, user_id, role, created_by)
		 VALUES ($1, $2, $3, $4)`,
		group.ID,
		createdBy,
		GroupMemberRoleOwner,
		createdBy,
	); err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *PostgresStore) ListGroupMembers(projectID, groupID uuid.UUID) ([]models.UserGroupMember, error) {
	if projectID == uuid.Nil || groupID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	var exists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM user_groups
		   WHERE id = $1
		     AND project_id = $2
		 )`,
		groupID,
		projectID,
	).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT gm.group_id, gm.user_id, gm.role, gm.created_at, gm.created_by, u.email, u.nickname, u.full_name
		 FROM user_group_members gm
		 JOIN users u ON u.id = gm.user_id
		 WHERE gm.group_id = $1
		 ORDER BY u.email, gm.user_id`,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]models.UserGroupMember, 0)
	for rows.Next() {
		var (
			item      models.UserGroupMember
			createdBy uuid.NullUUID
			fullName  sql.NullString
		)
		if err := rows.Scan(
			&item.GroupID,
			&item.UserID,
			&item.Role,
			&item.CreatedAt,
			&createdBy,
			&item.Email,
			&item.Nickname,
			&fullName,
		); err != nil {
			return nil, err
		}
		item.FullName = nullStringToString(fullName)
		if createdBy.Valid {
			id := createdBy.UUID
			item.CreatedBy = &id
		}
		item.Role = NormalizeGroupMemberRole(item.Role)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *PostgresStore) GetGroupMemberRole(projectID, groupID, userID uuid.UUID) (string, error) {
	if projectID == uuid.Nil || groupID == uuid.Nil || userID == uuid.Nil {
		return "", ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	var role string
	err := s.db.QueryRowContext(ctx,
		`SELECT gm.role
		 FROM user_group_members gm
		 JOIN user_groups g ON g.id = gm.group_id
		 WHERE gm.group_id = $1
		   AND gm.user_id = $2
		   AND g.project_id = $3`,
		groupID,
		userID,
		projectID,
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return NormalizeGroupMemberRole(role), nil
}

func (s *PostgresStore) ReplaceGroupMembers(projectID, groupID uuid.UUID, members []GroupMemberAssignment, createdBy uuid.UUID) error {
	if projectID == uuid.Nil || groupID == uuid.Nil || createdBy == uuid.Nil {
		return ErrInvalidPayload
	}

	seen := make(map[uuid.UUID]struct{}, len(members))
	userIDs := make([]uuid.UUID, 0, len(members))
	memberRoleByUser := make(map[uuid.UUID]string, len(members))
	ownerCount := 0
	for _, item := range members {
		if item.UserID == uuid.Nil {
			return ErrInvalidPayload
		}
		if _, exists := seen[item.UserID]; exists {
			return ErrInvalidPayload
		}
		role := NormalizeGroupMemberRole(item.Role)
		switch role {
		case GroupMemberRoleOwner, GroupMemberRoleEditor, GroupMemberRoleViewer:
		default:
			return ErrInvalidPayload
		}
		if role == GroupMemberRoleOwner {
			ownerCount++
		}
		seen[item.UserID] = struct{}{}
		userIDs = append(userIDs, item.UserID)
		memberRoleByUser[item.UserID] = role
	}
	if ownerCount == 0 {
		return ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM user_groups
		   WHERE id = $1
		     AND project_id = $2
		 )`,
		groupID,
		projectID,
	).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}

	var usersFound int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*)
		 FROM project_memberships pm
		 WHERE pm.project_id = $1
		   AND pm.user_id = ANY($2::uuid[])`,
		projectID,
		userIDs,
	).Scan(&usersFound); err != nil {
		return err
	}
	if usersFound != len(userIDs) {
		return ErrNotFound
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT created_by
		 FROM products
		 WHERE project_id = $1
		   AND owner_group_id = $2
		   AND created_by IS NOT NULL`,
		projectID,
		groupID,
	)
	if err != nil {
		return err
	}
	creatorIDs := make([]uuid.UUID, 0)
	for rows.Next() {
		var creatorID uuid.UUID
		if err := rows.Scan(&creatorID); err != nil {
			rows.Close()
			return err
		}
		creatorIDs = append(creatorIDs, creatorID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, creatorID := range creatorIDs {
		role, ok := memberRoleByUser[creatorID]
		if !ok || role != GroupMemberRoleOwner {
			return ErrForbidden
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM user_group_members
		 WHERE group_id = $1`,
		groupID,
	); err != nil {
		return err
	}

	for _, item := range members {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_group_members (group_id, user_id, role, created_by)
			 VALUES ($1, $2, $3, $4)`,
			groupID,
			item.UserID,
			NormalizeGroupMemberRole(item.Role),
			createdBy,
		); err != nil {
			if isForeignKeyViolation(err) {
				return ErrNotFound
			}
			if isUniqueViolation(err) {
				return ErrInvalidPayload
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func createDefaultOwnerGroupTx(ctx context.Context, tx *sql.Tx, projectID, actorID uuid.UUID, productName string) (uuid.UUID, error) {
	base := strings.TrimSpace(productName)
	if base == "" {
		base = "Product"
	}
	baseName := "Owners - " + base
	description := fmt.Sprintf("Primary owner group for product '%s'.", base)

	for i := 0; i < 100; i++ {
		name := baseName
		if i > 0 {
			name = fmt.Sprintf("%s (%d)", baseName, i+1)
		}

		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(
			   SELECT 1
			   FROM user_groups
			   WHERE project_id = $1
			     AND LOWER(name) = LOWER($2)
			 )`,
			projectID,
			name,
		).Scan(&exists); err != nil {
			return uuid.Nil, err
		}
		if exists {
			continue
		}

		var groupID uuid.UUID
		err := tx.QueryRowContext(ctx,
			`INSERT INTO user_groups (project_id, name, description, created_by)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id`,
			projectID,
			name,
			description,
			actorID,
		).Scan(&groupID)
		if isUniqueViolation(err) {
			return uuid.Nil, ErrAlreadyExists
		}
		if err != nil {
			if isForeignKeyViolation(err) {
				return uuid.Nil, ErrNotFound
			}
			return uuid.Nil, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO user_group_members (group_id, user_id, role, created_by)
			 VALUES ($1, $2, $3, $4)`,
			groupID,
			actorID,
			GroupMemberRoleOwner,
			actorID,
		); err != nil {
			if isForeignKeyViolation(err) {
				return uuid.Nil, ErrNotFound
			}
			return uuid.Nil, err
		}
		return groupID, nil
	}
	return uuid.Nil, ErrAlreadyExists
}

func (s *PostgresStore) CreateProductWithOwnerGroup(projectID uuid.UUID, name, description string, ownerGroupID *uuid.UUID, actorID uuid.UUID) (*models.Product, error) {
	name = strings.TrimSpace(name)
	if projectID == uuid.Nil || actorID == uuid.Nil || name == "" {
		return nil, ErrInvalidPayload
	}
	if ownerGroupID != nil && *ownerGroupID == uuid.Nil {
		return nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	if err := s.ensureProjectExists(ctx, projectID); err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var resolvedOwnerGroupID uuid.UUID
	if ownerGroupID != nil {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(
			   SELECT 1
			   FROM user_groups
			   WHERE id = $1
			     AND project_id = $2
			 )`,
			*ownerGroupID,
			projectID,
		).Scan(&exists); err != nil {
			return nil, err
		}
		if !exists {
			return nil, ErrNotFound
		}

		var memberRole string
		err := tx.QueryRowContext(ctx,
			`SELECT role
			 FROM user_group_members
			 WHERE group_id = $1
			   AND user_id = $2`,
			*ownerGroupID,
			actorID,
		).Scan(&memberRole)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrForbidden
		}
		if err != nil {
			return nil, err
		}
		if NormalizeGroupMemberRole(memberRole) != GroupMemberRoleOwner {
			return nil, ErrForbidden
		}
		resolvedOwnerGroupID = *ownerGroupID
	} else {
		groupID, err := createDefaultOwnerGroupTx(ctx, tx, projectID, actorID, name)
		if err != nil {
			return nil, err
		}
		resolvedOwnerGroupID = groupID
	}

	row := tx.QueryRowContext(ctx,
		`INSERT INTO products (project_id, name, description, owner_group_id, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (project_id, LOWER(name)) DO NOTHING
		 RETURNING id, project_id, name, description, owner_group_id, created_by, archived_at, created_at, updated_at`,
		projectID,
		name,
		strings.TrimSpace(description),
		resolvedOwnerGroupID,
		actorID,
	)
	product, err := scanProductWithOwnership(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAlreadyExists
	}
	if err != nil {
		if isForeignKeyViolation(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return product, nil
}

func (s *PostgresStore) GetEffectiveProductRole(projectID, productID, userID uuid.UUID) (string, error) {
	if projectID == uuid.Nil || productID == uuid.Nil || userID == uuid.Nil {
		return "", ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	var productExists bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(
		   SELECT 1
		   FROM products
		   WHERE id = $1
		     AND project_id = $2
		 )`,
		productID,
		projectID,
	).Scan(&productExists); err != nil {
		return "", err
	}
	if !productExists {
		return "", ErrNotFound
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT gm.role AS member_role,
		        CASE
		          WHEN gm.group_id = p.owner_group_id THEN 'OWNER'
		          ELSE pgg.role
		        END AS grant_role
		 FROM products p
		 JOIN user_group_members gm ON gm.user_id = $3
		 LEFT JOIN product_group_grants pgg
		   ON pgg.product_id = p.id
		  AND pgg.group_id = gm.group_id
		 WHERE p.id = $1
		   AND p.project_id = $2
		   AND (gm.group_id = p.owner_group_id OR pgg.group_id IS NOT NULL)`,
		productID,
		projectID,
		userID,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	effectiveRole := ""
	for rows.Next() {
		var memberRole string
		var grantRole string
		if err := rows.Scan(&memberRole, &grantRole); err != nil {
			return "", err
		}
		effectiveFromGroup := minRoleByRank(memberRole, grantRole)
		effectiveRole = maxRoleByRank(effectiveRole, effectiveFromGroup)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return effectiveRole, nil
}

func (s *PostgresStore) ListProductGroupGrants(projectID, productID uuid.UUID) (*models.Product, []models.ProductGroupGrant, error) {
	if projectID == uuid.Nil || productID == uuid.Nil {
		return nil, nil, ErrInvalidPayload
	}

	ctx, cancel := s.ctx()
	defer cancel()

	productRow := s.db.QueryRowContext(ctx,
		`SELECT id, project_id, name, description, owner_group_id, created_by, archived_at, created_at, updated_at
		 FROM products
		 WHERE id = $1
		   AND project_id = $2`,
		productID,
		projectID,
	)
	product, err := scanProductWithOwnership(productRow)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT product_id, group_id, role, created_at, created_by
		 FROM product_group_grants
		 WHERE product_id = $1
		 ORDER BY group_id`,
		productID,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	grants := make([]models.ProductGroupGrant, 0)
	for rows.Next() {
		var (
			item      models.ProductGroupGrant
			createdBy uuid.NullUUID
		)
		if err := rows.Scan(
			&item.ProductID,
			&item.GroupID,
			&item.Role,
			&item.CreatedAt,
			&createdBy,
		); err != nil {
			return nil, nil, err
		}
		if createdBy.Valid {
			id := createdBy.UUID
			item.CreatedBy = &id
		}
		item.Role = normalizeProductGrantRole(item.Role)
		grants = append(grants, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return product, grants, nil
}

func (s *PostgresStore) ReplaceProductGroupGrants(projectID, productID uuid.UUID, grants []ProductGroupGrantAssignment, createdBy uuid.UUID) error {
	if projectID == uuid.Nil || productID == uuid.Nil || createdBy == uuid.Nil {
		return ErrInvalidPayload
	}

	seenGroups := make(map[uuid.UUID]struct{}, len(grants))
	groupIDs := make([]uuid.UUID, 0, len(grants))
	normalized := make([]ProductGroupGrantAssignment, 0, len(grants))
	for _, grant := range grants {
		if grant.GroupID == uuid.Nil {
			return ErrInvalidPayload
		}
		if _, exists := seenGroups[grant.GroupID]; exists {
			return ErrInvalidPayload
		}
		role := normalizeProductGrantRole(grant.Role)
		switch role {
		case ProductGroupGrantRoleEditor, ProductGroupGrantRoleViewer:
		default:
			return ErrInvalidPayload
		}
		seenGroups[grant.GroupID] = struct{}{}
		groupIDs = append(groupIDs, grant.GroupID)
		normalized = append(normalized, ProductGroupGrantAssignment{
			GroupID: grant.GroupID,
			Role:    role,
		})
	}

	ctx, cancel := s.ctx()
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var ownerGroupID uuid.NullUUID
	err = tx.QueryRowContext(ctx,
		`SELECT owner_group_id
		 FROM products
		 WHERE id = $1
		   AND project_id = $2`,
		productID,
		projectID,
	).Scan(&ownerGroupID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	if ownerGroupID.Valid {
		if _, exists := seenGroups[ownerGroupID.UUID]; exists {
			return ErrInvalidPayload
		}
	}

	if len(groupIDs) > 0 {
		var groupsFound int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*)
			 FROM user_groups
			 WHERE project_id = $1
			   AND id = ANY($2::uuid[])`,
			projectID,
			groupIDs,
		).Scan(&groupsFound); err != nil {
			return err
		}
		if groupsFound != len(groupIDs) {
			return ErrNotFound
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM product_group_grants
		 WHERE product_id = $1`,
		productID,
	); err != nil {
		return err
	}

	for _, grant := range normalized {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO product_group_grants (product_id, group_id, role, created_by)
			 VALUES ($1, $2, $3, $4)`,
			productID,
			grant.GroupID,
			grant.Role,
			createdBy,
		); err != nil {
			if isForeignKeyViolation(err) {
				return ErrNotFound
			}
			if isUniqueViolation(err) {
				return ErrInvalidPayload
			}
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}
