package handlers

import (
	"net/http"

	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

func requireProjectRole(userCtx auth.UserContext, st store.Store, projectID uuid.UUID, requiredRole string) *resolveError {
	role, err := st.GetProjectRole(userCtx.ID, projectID)
	if err == store.ErrNotFound {
		return &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "No project access assigned for this user.",
		}
	}
	if err != nil {
		return &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve project role.",
			err:    err,
		}
	}
	if !store.ProjectRoleAtLeast(role, requiredRole) {
		return &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "Insufficient project role.",
		}
	}
	return nil
}

func resolveActiveProjectWithRole(r *http.Request, st store.Store, requiredRole string) (auth.UserContext, *models.Project, *resolveError) {
	userCtx, project, resolveErr := resolveActiveProject(r, st)
	if resolveErr != nil {
		return auth.UserContext{}, nil, resolveErr
	}
	if authzErr := requireProjectRole(userCtx, st, project.ID, requiredRole); authzErr != nil {
		return auth.UserContext{}, nil, authzErr
	}
	return userCtx, project, nil
}
