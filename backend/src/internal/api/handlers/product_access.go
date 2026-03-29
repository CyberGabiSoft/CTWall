package handlers

import (
	"net/http"
	"strings"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

type productAccessGrantRequest struct {
	GroupID string `json:"groupId"`
	Role    string `json:"role"`
}

type productAccessSetRequest struct {
	Grants []productAccessGrantRequest `json:"grants"`
}

type productAccessGrantResponse struct {
	GroupID string `json:"groupId"`
	Role    string `json:"role"`
}

type productAccessResponse struct {
	OwnerGroupID string                       `json:"ownerGroupId,omitempty"`
	CreatedBy    string                       `json:"createdBy,omitempty"`
	Grants       []productAccessGrantResponse `json:"grants"`
}

func canManageProductAccess(st store.Store, projectID, productID, userID uuid.UUID) (bool, *resolveError) {
	projectRole, err := st.GetProjectRole(userID, projectID)
	if err == store.ErrNotFound {
		return false, &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "No project access assigned for this user.",
		}
	}
	if err != nil {
		return false, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve project role.",
			err:    err,
		}
	}
	if store.ProjectRoleAtLeast(projectRole, store.ProjectRoleAdmin) {
		return true, nil
	}
	if !store.ProjectRoleAtLeast(projectRole, store.ProjectRoleWriter) {
		return false, &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "Insufficient project role.",
		}
	}

	effectiveRole, err := st.GetEffectiveProductRole(projectID, productID, userID)
	if err == store.ErrNotFound {
		return false, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Product not found.",
		}
	}
	if err != nil {
		return false, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve effective product role.",
			err:    err,
		}
	}
	if effectiveRole != store.GroupMemberRoleOwner {
		return false, &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "Product owner role required.",
		}
	}
	return true, nil
}

func mapProductAccessResponse(product *models.Product, grants []models.ProductGroupGrant) productAccessResponse {
	response := productAccessResponse{
		Grants: make([]productAccessGrantResponse, 0, len(grants)),
	}
	if product != nil {
		if product.OwnerGroupID != nil {
			response.OwnerGroupID = product.OwnerGroupID.String()
		}
		if product.CreatedBy != nil {
			response.CreatedBy = product.CreatedBy.String()
		}
	}
	for _, grant := range grants {
		response.Grants = append(response.Grants, productAccessGrantResponse{
			GroupID: grant.GroupID.String(),
			Role:    strings.ToUpper(strings.TrimSpace(grant.Role)),
		})
	}
	return response
}

func GetProductAccessHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		productID, err := uuid.Parse(strings.TrimSpace(r.PathValue("productId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productId.", err)
			return
		}

		if _, authzErr := canManageProductAccess(st, project.ID, productID, userCtx.ID); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		product, grants, err := st.ListProductGroupGrants(project.ID, productID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product access.", err)
			return
		}

		writeJSON(w, http.StatusOK, mapProductAccessResponse(product, grants))
	}
}

func PutProductAccessHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		productID, err := uuid.Parse(strings.TrimSpace(r.PathValue("productId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productId.", err)
			return
		}

		if _, authzErr := canManageProductAccess(st, project.ID, productID, userCtx.ID); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		var req productAccessSetRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}

		assignments := make([]store.ProductGroupGrantAssignment, 0, len(req.Grants))
		for _, grant := range req.Grants {
			groupID, err := uuid.Parse(strings.TrimSpace(grant.GroupID))
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid grants payload.", err)
				return
			}
			role := strings.ToUpper(strings.TrimSpace(grant.Role))
			switch role {
			case store.ProductGroupGrantRoleEditor, store.ProductGroupGrantRoleViewer:
			default:
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid grants payload.", nil)
				return
			}
			assignments = append(assignments, store.ProductGroupGrantAssignment{
				GroupID: groupID,
				Role:    role,
			})
		}

		if err := st.ReplaceProductGroupGrants(project.ID, productID, assignments, userCtx.ID); err != nil {
			if err == store.ErrInvalidPayload {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid grants payload.", nil)
				return
			}
			if err == store.ErrNotFound {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Product or groups not found in project.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update product access.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAuthZ,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleWrite,
			EventKey:  "authz.product_group_grants_set",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Product access updated",
			Message:   "Product group grants were replaced.",
			Component: component,
		}, map[string]any{
			"productId":  productID.String(),
			"grantCount": len(assignments),
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "PRODUCT_GROUP_GRANTS_SET",
				EntityType: "PRODUCT",
				EntityID:   &productID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		product, grants, err := st.ListProductGroupGrants(project.ID, productID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load updated product access.", err)
			return
		}
		writeJSON(w, http.StatusOK, mapProductAccessResponse(product, grants))
	}
}
