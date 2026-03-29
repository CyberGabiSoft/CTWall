package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

const projectHeaderName = "X-Project-ID"

func isAdminRole(role auth.Role) bool {
	return role == auth.RoleAdmin
}

func resolveUserContext(r *http.Request) (auth.UserContext, *resolveError) {
	userCtx, ok := auth.UserFromContext(r.Context())
	if !ok {
		return auth.UserContext{}, &resolveError{
			status: http.StatusUnauthorized,
			title:  "Unauthorized",
			detail: "Authentication required.",
			err:    errors.New("missing user context"),
		}
	}
	return userCtx, nil
}

func resolveActiveProject(r *http.Request, st store.Store) (auth.UserContext, *models.Project, *resolveError) {
	userCtx, resolveErr := resolveUserContext(r)
	if resolveErr != nil {
		return auth.UserContext{}, nil, resolveErr
	}

	if err := st.EnsureUserSettings(userCtx.ID); err != nil {
		return auth.UserContext{}, nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to initialize user settings.",
			err:    err,
		}
	}

	includeAll := isAdminRole(userCtx.Role)
	headerProjectID := strings.TrimSpace(r.Header.Get(projectHeaderName))
	if headerProjectID != "" {
		projectID, err := uuid.Parse(headerProjectID)
		if err != nil {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Invalid X-Project-ID header.",
				err:    err,
			}
		}
		hasAccess, err := st.UserHasProjectAccess(userCtx.ID, projectID, includeAll)
		if err != nil {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusInternalServerError,
				title:  "Internal Error",
				detail: "Failed to resolve project access.",
				err:    err,
			}
		}
		if !hasAccess {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusForbidden,
				title:  "Forbidden",
				detail: "No access to selected project.",
			}
		}
		if err := st.SetSelectedProjectID(userCtx.ID, projectID); err != nil {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusInternalServerError,
				title:  "Internal Error",
				detail: "Failed to persist selected project.",
				err:    err,
			}
		}
		project, err := st.GetProject(projectID)
		if err == store.ErrNotFound {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusNotFound,
				title:  "Not Found",
				detail: "Project not found.",
			}
		}
		if err != nil {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusInternalServerError,
				title:  "Internal Error",
				detail: "Failed to load selected project.",
				err:    err,
			}
		}
		return userCtx, project, nil
	}

	selectedProjectID, err := st.GetSelectedProjectID(userCtx.ID)
	if err != nil {
		return auth.UserContext{}, nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve selected project.",
			err:    err,
		}
	}
	if selectedProjectID != nil {
		hasAccess, err := st.UserHasProjectAccess(userCtx.ID, *selectedProjectID, includeAll)
		if err != nil {
			return auth.UserContext{}, nil, &resolveError{
				status: http.StatusInternalServerError,
				title:  "Internal Error",
				detail: "Failed to resolve selected project access.",
				err:    err,
			}
		}
		if hasAccess {
			project, err := st.GetProject(*selectedProjectID)
			if err == nil {
				return userCtx, project, nil
			}
			if err != store.ErrNotFound {
				return auth.UserContext{}, nil, &resolveError{
					status: http.StatusInternalServerError,
					title:  "Internal Error",
					detail: "Failed to load selected project.",
					err:    err,
				}
			}
		}
	}

	projects, err := st.ListProjectsForUser(userCtx.ID, includeAll)
	if err != nil {
		return auth.UserContext{}, nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to list accessible projects.",
			err:    err,
		}
	}
	if len(projects) == 0 {
		return auth.UserContext{}, nil, &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "No project access assigned for this user.",
		}
	}

	selected := projects[0]
	if err := st.SetSelectedProjectID(userCtx.ID, selected.ID); err != nil {
		return auth.UserContext{}, nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to persist selected project.",
			err:    err,
		}
	}
	return userCtx, &selected, nil
}
