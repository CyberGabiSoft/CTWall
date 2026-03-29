package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestRequireProjectRoleDecisions(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	userCtx := auth.UserContext{ID: uuid.New()}
	projectID := uuid.New()

	notFound := tests.StoreWrapper{Store: pgStore, GetProjectRoleErr: store.ErrNotFound}
	if err := requireProjectRole(userCtx, notFound, projectID, store.ProjectRoleReader); err == nil || err.status != http.StatusForbidden {
		t.Fatalf("expected forbidden for missing project role, got %+v", err)
	}

	internalErr := tests.StoreWrapper{Store: pgStore, GetProjectRoleErr: errors.New("db unavailable")}
	if err := requireProjectRole(userCtx, internalErr, projectID, store.ProjectRoleReader); err == nil || err.status != http.StatusInternalServerError {
		t.Fatalf("expected internal error for role resolution failure, got %+v", err)
	}

	insufficient := tests.StoreWrapper{Store: pgStore, GetProjectRoleValue: store.ProjectRoleReader}
	if err := requireProjectRole(userCtx, insufficient, projectID, store.ProjectRoleWriter); err == nil || err.status != http.StatusForbidden {
		t.Fatalf("expected forbidden for insufficient role, got %+v", err)
	}

	allowed := tests.StoreWrapper{Store: pgStore, GetProjectRoleValue: store.ProjectRoleAdmin}
	if err := requireProjectRole(userCtx, allowed, projectID, store.ProjectRoleWriter); err != nil {
		t.Fatalf("expected role check to pass, got %+v", err)
	}
}

func TestResolveActiveProjectWithRoleDelegatesAuthz(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	user, err := pgStore.CreateUser("project-authz@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Project Authz")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	projects, err := pgStore.ListProjectsForUser(user.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID

	t.Run("missing auth context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
		_, _, resolveErr := resolveActiveProjectWithRole(req, pgStore, store.ProjectRoleReader)
		if resolveErr == nil || resolveErr.status != http.StatusUnauthorized {
			t.Fatalf("expected unauthorized resolve error, got %+v", resolveErr)
		}
	})

	t.Run("authz denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
		req.Header.Set(projectHeaderName, projectID.String())
		req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
			ID:          user.ID,
			Role:        auth.RoleAdmin,
			AccountType: auth.AccountTypeUser,
			Email:       user.Email,
		}))
		wrapped := tests.StoreWrapper{Store: pgStore, GetProjectRoleErr: store.ErrNotFound}
		_, _, resolveErr := resolveActiveProjectWithRole(req, wrapped, store.ProjectRoleReader)
		if resolveErr == nil || resolveErr.status != http.StatusForbidden {
			t.Fatalf("expected forbidden resolve error, got %+v", resolveErr)
		}
	})

	t.Run("authz allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
		req.Header.Set(projectHeaderName, projectID.String())
		req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
			ID:          user.ID,
			Role:        auth.RoleAdmin,
			AccountType: auth.AccountTypeUser,
			Email:       user.Email,
		}))
		wrapped := tests.StoreWrapper{Store: pgStore, GetProjectRoleValue: store.ProjectRoleAdmin}
		gotUser, gotProject, resolveErr := resolveActiveProjectWithRole(req, wrapped, store.ProjectRoleReader)
		if resolveErr != nil {
			t.Fatalf("expected success, got %+v", resolveErr)
		}
		if gotProject == nil || gotProject.ID != projectID {
			t.Fatalf("expected selected project %s, got %+v", projectID, gotProject)
		}
		if gotUser.ID != user.ID {
			t.Fatalf("expected user %s, got %s", user.ID, gotUser.ID)
		}
	})
}

