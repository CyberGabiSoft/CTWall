package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

type projectContextStore struct {
	tests.StoreWrapper

	ensureUserSettingsErr   error
	userHasProjectAccess    bool
	userHasProjectAccessErr error
	selectedProjectID       *uuid.UUID
	getSelectedProjectIDErr error
	setSelectedProjectIDErr error
	listProjectsForUser     []models.Project
	listProjectsForUserErr  error
	projectByID             *models.Project
	getProjectErr           error
	lastIncludeAll          bool
}

func (s *projectContextStore) EnsureUserSettings(_ uuid.UUID) error {
	return s.ensureUserSettingsErr
}

func (s *projectContextStore) UserHasProjectAccess(_ uuid.UUID, _ uuid.UUID, includeAll bool) (bool, error) {
	s.lastIncludeAll = includeAll
	if s.userHasProjectAccessErr != nil {
		return false, s.userHasProjectAccessErr
	}
	return s.userHasProjectAccess, nil
}

func (s *projectContextStore) GetSelectedProjectID(_ uuid.UUID) (*uuid.UUID, error) {
	if s.getSelectedProjectIDErr != nil {
		return nil, s.getSelectedProjectIDErr
	}
	return s.selectedProjectID, nil
}

func (s *projectContextStore) SetSelectedProjectID(_ uuid.UUID, _ uuid.UUID) error {
	return s.setSelectedProjectIDErr
}

func (s *projectContextStore) ListProjectsForUser(_ uuid.UUID, includeAll bool) ([]models.Project, error) {
	s.lastIncludeAll = includeAll
	if s.listProjectsForUserErr != nil {
		return nil, s.listProjectsForUserErr
	}
	return s.listProjectsForUser, nil
}

func (s *projectContextStore) GetProject(id uuid.UUID) (*models.Project, error) {
	if s.getProjectErr != nil {
		return nil, s.getProjectErr
	}
	if s.projectByID != nil && s.projectByID.ID == id {
		project := *s.projectByID
		return &project, nil
	}
	return nil, store.ErrNotFound
}

func authedRequest(method, path string, role auth.Role) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	return req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
		ID:          uuid.New(),
		Role:        role,
		AccountType: auth.AccountTypeUser,
		Email:       "user@example.com",
	}))
}

func TestResolveUserContextMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	_, resolveErr := resolveUserContext(req)
	if resolveErr == nil || resolveErr.status != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized resolve error, got %+v", resolveErr)
	}
}

func TestResolveActiveProjectBranches(t *testing.T) {
	projectID := uuid.New()
	project := models.Project{ID: projectID, Name: "Project A"}

	testCases := []struct {
		name       string
		request    *http.Request
		store      *projectContextStore
		wantStatus int
		wantOK     bool
	}{
		{
			name:       "ensure user settings failure",
			request:    authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store:      &projectContextStore{ensureUserSettingsErr: errors.New("settings failure")},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "invalid project header",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, "bad-uuid")
				return req
			}(),
			store:      &projectContextStore{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "project access lookup failure",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccessErr: errors.New("lookup failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "project access denied",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccess: false,
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "set selected project failure",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccess: true,
				setSelectedProjectIDErr: errors.New("persist failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "selected project not found by header",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccess: true,
				getProjectErr:        store.ErrNotFound,
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name: "selected project load failure by header",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccess: true,
				getProjectErr:        errors.New("load failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "header flow success",
			request: func() *http.Request {
				req := authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader)
				req.Header.Set(projectHeaderName, projectID.String())
				return req
			}(),
			store: &projectContextStore{
				userHasProjectAccess: true,
				projectByID:          &project,
			},
			wantOK: true,
		},
		{
			name:    "selected project lookup failure",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				getSelectedProjectIDErr: errors.New("selected failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "selected project access lookup failure",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				selectedProjectID:       &projectID,
				userHasProjectAccessErr: errors.New("access failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "selected project load failure",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				selectedProjectID:    &projectID,
				userHasProjectAccess: true,
				getProjectErr:        errors.New("project load failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "list projects failure",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				selectedProjectID:      &projectID,
				userHasProjectAccess:   false,
				listProjectsForUserErr: errors.New("list failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "no projects accessible",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				listProjectsForUser: []models.Project{},
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:    "fallback set selected project failure",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				listProjectsForUser:   []models.Project{project},
				setSelectedProjectIDErr: errors.New("persist failure"),
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:    "fallback selection success",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				listProjectsForUser: []models.Project{project},
			},
			wantOK: true,
		},
		{
			name:    "selected project missing falls back and succeeds",
			request: authedRequest(http.MethodGet, "/api/v1/products", auth.RoleReader),
			store: &projectContextStore{
				selectedProjectID:    &projectID,
				userHasProjectAccess: true,
				getProjectErr:        store.ErrNotFound,
				listProjectsForUser:  []models.Project{project},
			},
			wantOK: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Provide embedded Store implementation for methods not explicitly overridden.
			pgStore, _ := tests.NewPostgresTestStore(t)
			tc.store.StoreWrapper = tests.StoreWrapper{Store: pgStore}

			userCtx, gotProject, resolveErr := resolveActiveProject(tc.request, tc.store)
			if tc.wantOK {
				if resolveErr != nil {
					t.Fatalf("expected success, got %+v", resolveErr)
				}
				if gotProject == nil {
					t.Fatalf("expected project")
				}
				if userCtx.ID == uuid.Nil {
					t.Fatalf("expected user context")
				}
				if userCtx.Role == auth.RoleReader && tc.store.lastIncludeAll {
					t.Fatalf("expected includeAll=false for non-admin user")
				}
				return
			}
			if resolveErr == nil {
				t.Fatalf("expected resolve error with status %d", tc.wantStatus)
			}
			if resolveErr.status != tc.wantStatus {
				t.Fatalf("expected status %d, got %+v", tc.wantStatus, resolveErr)
			}
		})
	}
}

