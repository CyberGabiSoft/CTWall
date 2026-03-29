package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type projectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type projectDeleteRequest struct {
	Acknowledge bool `json:"acknowledge"`
}

type projectMemberRequest struct {
	UserID      string `json:"userId"`
	ProjectRole string `json:"projectRole"`
}

type projectMembersRequest struct {
	Members []projectMemberRequest `json:"members"`
}

type selectedProjectRequest struct {
	ProjectID string `json:"projectId"`
}

type selectedProjectResponse struct {
	ProjectID   string `json:"projectId"`
	Name        string `json:"name"`
	ProjectRole string `json:"projectRole"`
}

func ListProjectsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		projects, err := st.ListProjectsForUser(userCtx.ID, isAdminRole(userCtx.Role))
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list projects.", err)
			return
		}
		writeJSON(w, http.StatusOK, paginate(projects, page, pageSize))
	}
}

func CreateProjectHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		var req projectRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		name, err := validateName("name", req.Name, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		project, err := st.CreateProject(name, sanitizePlainText(req.Description), &userCtx.ID)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Project already exists.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create project.", err)
			return
		}

		// Creator is always added as ADMIN member for safe bootstrap.
		if err := st.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
			{
				UserID:      userCtx.ID,
				ProjectRole: store.ProjectRoleAdmin,
			},
		}, &userCtx.ID); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to initialize project members.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryConfig,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  "config.project_create",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Project created",
			Message:   "Admin created a project workspace.",
			Component: component,
		}, map[string]any{
			"projectName": project.Name,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PROJECT_CREATE",
				EntityType: "PROJECT",
				EntityID:   &project.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		writeJSON(w, http.StatusCreated, project)
	}
}

func UpdateProjectHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		projectID, err := uuid.Parse(strings.TrimSpace(r.PathValue("projectId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid projectId.", err)
			return
		}

		var req projectRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		name, err := validateName("name", req.Name, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		project, err := st.UpdateProject(projectID, name, sanitizePlainText(req.Description))
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project not found.", nil)
			return
		}
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Project already exists.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update project.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryConfig,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  "config.project_update",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Project updated",
			Message:   "Admin updated project metadata.",
			Component: component,
		}, map[string]any{
			"projectName":        project.Name,
			"projectDescription": project.Description,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PROJECT_UPDATE",
				EntityType: "PROJECT",
				EntityID:   &project.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		writeJSON(w, http.StatusOK, project)
	}
}

func DeleteProjectHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		projectID, err := uuid.Parse(strings.TrimSpace(r.PathValue("projectId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid projectId.", err)
			return
		}

		var req projectDeleteRequest
		if err := decodeOptionalJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		if !req.Acknowledge {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Project delete requires acknowledge=true.", nil)
			return
		}

		project, deletedProducts, err := st.DeleteProject(projectID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete project.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		deletedProductsDetails := make([]map[string]string, 0, len(deletedProducts))
		for _, product := range deletedProducts {
			deletedProductsDetails = append(deletedProductsDetails, map[string]string{
				"id":   product.ID.String(),
				"name": product.Name,
			})
		}
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryConfig,
			Severity:  eventmeta.SeverityWarn,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  "config.project_delete",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Project deleted",
			Message:   "Admin deleted a project workspace.",
			Component: component,
		}, map[string]any{
			"acknowledge":     true,
			"projectName":     project.Name,
			"deletedProducts": deletedProductsDetails,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PROJECT_DELETE",
				EntityType: "PROJECT",
				EntityID:   &project.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func ListProjectMembersHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		projectID, err := uuid.Parse(strings.TrimSpace(r.PathValue("projectId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid projectId.", err)
			return
		}

		if !isAdminRole(userCtx.Role) {
			if authzErr := requireProjectRole(userCtx, st, projectID, store.ProjectRoleAdmin); authzErr != nil {
				writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
				return
			}
		}

		users, err := st.ListProjectMembers(projectID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list project members.", err)
			return
		}
		writeJSON(w, http.StatusOK, users)
	}
}

func ReplaceProjectMembersHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		projectID, err := uuid.Parse(strings.TrimSpace(r.PathValue("projectId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid projectId.", err)
			return
		}
		if !isAdminRole(userCtx.Role) {
			if authzErr := requireProjectRole(userCtx, st, projectID, store.ProjectRoleAdmin); authzErr != nil {
				writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
				return
			}
		}

		var req projectMembersRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}

		members := make([]store.ProjectMemberAssignment, 0, len(req.Members))
		memberDetails := make([]map[string]string, 0, len(req.Members))
		for _, raw := range req.Members {
			id, err := uuid.Parse(strings.TrimSpace(raw.UserID))
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", err)
				return
			}
			role := store.NormalizeProjectRole(raw.ProjectRole)
			if !store.IsValidProjectRole(role) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", nil)
				return
			}
			members = append(members, store.ProjectMemberAssignment{
				UserID:      id,
				ProjectRole: role,
			})
			memberDetails = append(memberDetails, map[string]string{
				"userId":      id.String(),
				"projectRole": role,
			})
		}

		if err := st.ReplaceProjectMembers(projectID, members, &userCtx.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Project or users not found.", nil)
				return
			}
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", nil)
				return
			}
			if errors.Is(err, store.ErrInvalidStateTransition) {
				writeProblem(w, r, http.StatusConflict, "Conflict", "Project membership invariants violated.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update project members.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAccount,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  "account.project_members_set",
			ProjectID: projectID.String(),
			TraceID:   traceID,
			Title:     "Project members updated",
			Message:   "Admin replaced project memberships.",
			Component: component,
		}, map[string]any{
			"members": memberDetails,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PROJECT_MEMBERS_SET",
				EntityType: "PROJECT",
				EntityID:   &projectID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func GetSelectedProjectHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		projectRole, roleErr := resolveSelectedProjectRole(st, userCtx.ID, project.ID)
		if roleErr != nil {
			writeProblem(w, r, roleErr.status, roleErr.title, roleErr.detail, roleErr.err)
			return
		}
		writeJSON(w, http.StatusOK, selectedProjectResponse{
			ProjectID:   project.ID.String(),
			Name:        project.Name,
			ProjectRole: projectRole,
		})
	}
}

func SetSelectedProjectHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, resolveErr := resolveUserContext(r)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		var req selectedProjectRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		projectID, err := uuid.Parse(strings.TrimSpace(req.ProjectID))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid projectId.", err)
			return
		}

		hasAccess, err := st.UserHasProjectAccess(userCtx.ID, projectID, isAdminRole(userCtx.Role))
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve project access.", err)
			return
		}
		if !hasAccess {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "No access to selected project.", nil)
			return
		}
		if err := st.SetSelectedProjectID(userCtx.ID, projectID); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save selected project.", err)
			return
		}
		project, err := st.GetProject(projectID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Project not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load selected project.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAccount,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleRead,
			EventKey:  "account.project_select",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Project selected",
			Message:   "User selected an active project.",
			Component: component,
		}, map[string]any{
			"projectName": project.Name,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PROJECT_SELECT",
				EntityType: "PROJECT",
				EntityID:   &project.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, false)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		projectRole, roleErr := resolveSelectedProjectRole(st, userCtx.ID, project.ID)
		if roleErr != nil {
			writeProblem(w, r, roleErr.status, roleErr.title, roleErr.detail, roleErr.err)
			return
		}

		writeJSON(w, http.StatusOK, selectedProjectResponse{
			ProjectID:   project.ID.String(),
			Name:        project.Name,
			ProjectRole: projectRole,
		})
	}
}

func resolveSelectedProjectRole(st store.Store, userID, projectID uuid.UUID) (string, *resolveError) {
	role, err := st.GetProjectRole(userID, projectID)
	if err == store.ErrNotFound {
		return "NONE", nil
	}
	if err != nil {
		return "", &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve selected project role.",
			err:    err,
		}
	}
	return role, nil
}
