package handlers

import (
	"net/http"
	"strings"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type groupMemberRequest struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

type groupMembersSetRequest struct {
	Members []groupMemberRequest `json:"members"`
}

func PutGroupMembersHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		groupID, err := uuid.Parse(strings.TrimSpace(r.PathValue("groupId")))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid groupId.", err)
			return
		}

		projectRole, err := st.GetProjectRole(userCtx.ID, project.ID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "No project access assigned for this user.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve project role.", err)
			return
		}
		if !store.ProjectRoleAtLeast(projectRole, store.ProjectRoleAdmin) {
			if !store.ProjectRoleAtLeast(projectRole, store.ProjectRoleWriter) {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Insufficient project role.", nil)
				return
			}
			memberRole, err := st.GetGroupMemberRole(project.ID, groupID, userCtx.ID)
			if err == store.ErrNotFound {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Only group OWNER can manage members.", nil)
				return
			}
			if err != nil {
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve group membership.", err)
				return
			}
			if memberRole != store.GroupMemberRoleOwner {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Only group OWNER can manage members.", nil)
				return
			}
		}

		var req groupMembersSetRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		assignments := make([]store.GroupMemberAssignment, 0, len(req.Members))
		for _, member := range req.Members {
			userID, err := uuid.Parse(strings.TrimSpace(member.UserID))
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", err)
				return
			}
			role := strings.ToUpper(strings.TrimSpace(member.Role))
			switch role {
			case store.GroupMemberRoleOwner, store.GroupMemberRoleEditor, store.GroupMemberRoleViewer:
			default:
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", nil)
				return
			}
			assignments = append(assignments, store.GroupMemberAssignment{
				UserID: userID,
				Role:   role,
			})
		}

		if err := st.ReplaceGroupMembers(project.ID, groupID, assignments, userCtx.ID); err != nil {
			if err == store.ErrInvalidPayload {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid members payload.", nil)
				return
			}
			if err == store.ErrForbidden {
				writeProblem(w, r, http.StatusForbidden, "Forbidden", "Creator cannot be removed or downgraded from owner group.", nil)
				return
			}
			if err == store.ErrNotFound {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Group or users not found in project.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update group members.", err)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryAccount,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleWrite,
			EventKey:  "account.group_members_set",
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Group members updated",
			Message:   "Group membership was replaced.",
			Component: component,
		}, map[string]any{
			"groupId":     groupID.String(),
			"memberCount": len(assignments),
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "GROUP_MEMBERS_SET",
				EntityType: "GROUP",
				EntityID:   &groupID,
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
