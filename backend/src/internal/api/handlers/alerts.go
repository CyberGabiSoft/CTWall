package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

type alertGroupsListResponse struct {
	Items      []models.AlertGroup `json:"items"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"pageSize"`
	Total      int                 `json:"total"`
	TotalPages int                 `json:"totalPages"`
}

type alertOccurrencesListResponse struct {
	Items      []models.AlertOccurrence `json:"items"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"pageSize"`
	Total      int                      `json:"total"`
	TotalPages int                      `json:"totalPages"`
}

func ListAlertGroupsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}
		if pageSize > 100 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		q, err := buildAlertGroupsQuery(r, project.ID, pageSize, offset)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
			return
		}

		items, total, err := st.ListAlertGroups(*q)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list alert groups.", err)
			return
		}
		totalPages := 1
		if pageSize > 0 {
			totalPages = (total + pageSize - 1) / pageSize
			if totalPages < 1 {
				totalPages = 1
			}
		}
		writeJSON(w, http.StatusOK, alertGroupsListResponse{
			Items:      items,
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		})
	}
}

func GetAlertGroupHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := strings.TrimSpace(r.PathValue("id"))
		groupID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid alert group id.", err)
			return
		}

		item, err := st.GetAlertGroup(project.ID, groupID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load alert group.", err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

func ListAlertOccurrencesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}
		if pageSize > 200 {
			pageSize = 200
		}
		offset := (page - 1) * pageSize

		q, err := buildAlertOccurrencesQuery(r, project.ID, pageSize, offset)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
			return
		}

		items, total, err := st.ListAlertOccurrences(*q)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list alert occurrences.", err)
			return
		}
		totalPages := 1
		if pageSize > 0 {
			totalPages = (total + pageSize - 1) / pageSize
			if totalPages < 1 {
				totalPages = 1
			}
		}
		writeJSON(w, http.StatusOK, alertOccurrencesListResponse{
			Items:      items,
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		})
	}
}

func AcknowledgeAlertGroupHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, st, store.ProjectRoleAdmin)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := strings.TrimSpace(r.PathValue("id"))
		groupID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid alert group id.", err)
			return
		}

		group, err := st.GetAlertGroup(project.ID, groupID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to acknowledge alert group.", err)
			return
		}
		if strings.EqualFold(group.Category, string(eventmeta.CategoryMalware)) {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Malware alert groups are managed via Explorer triage.", nil)
			return
		}

		if err := st.AcknowledgeAlertGroup(project.ID, groupID, userCtx.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to acknowledge alert group.", err)
			return
		}

		writeAlertStatusAudit(auditWriter, r, userCtx.ID, project.ID, group, "alerts.acknowledge", "ALERT_ACKNOWLEDGE", "Alert acknowledged", "Alert group acknowledged by admin.")
		w.WriteHeader(http.StatusNoContent)
	}
}

func CloseAlertGroupHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, st, store.ProjectRoleAdmin)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := strings.TrimSpace(r.PathValue("id"))
		groupID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid alert group id.", err)
			return
		}

		group, err := st.GetAlertGroup(project.ID, groupID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to close alert group.", err)
			return
		}
		if strings.EqualFold(group.Category, string(eventmeta.CategoryMalware)) {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Malware alert groups are managed via Explorer triage.", nil)
			return
		}

		if err := st.CloseAlertGroup(project.ID, groupID, userCtx.ID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Alert group not found.", nil)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to close alert group.", err)
			return
		}

		writeAlertStatusAudit(auditWriter, r, userCtx.ID, project.ID, group, "alerts.close", "ALERT_CLOSE", "Alert closed", "Alert group closed by admin.")
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeAlertStatusAudit(auditWriter *audit.Writer, r *http.Request, actorID, projectID uuid.UUID, group *models.AlertGroup, eventKey, action, title, message string) {
	if auditWriter == nil || group == nil {
		return
	}
	cat := eventmeta.CategorySystem
	if eventmeta.ValidCategory(group.Category) {
		cat = eventmeta.Category(group.Category)
	}
	traceID := middleware.TraceIDFromContext(r.Context())
	component := middleware.ComponentFromContext(r.Context())
	details, err := audit.BuildDetails(audit.DetailsBase{
		Category:  cat,
		Severity:  eventmeta.SeverityInfo,
		MinRole:   eventmeta.MinRoleAdmin,
		EventKey:  eventKey,
		TraceID:   traceID,
		ProjectID: projectID.String(),
		Title:     title,
		Message:   message,
		Component: component,
	}, map[string]any{
		"alertGroupId": group.ID.String(),
		"groupKey":     group.GroupKey,
		"type":         group.Type,
		"category":     group.Category,
		"severity":     group.Severity,
	})
	if err != nil {
		return
	}
	entry := store.AuditLogEntry{
		ActorID:    &actorID,
		Action:     action,
		EntityType: "alert_group",
		EntityID:   &group.ID,
		Details:    details,
		IPAddress:  audit.IPFromRequest(r),
	}
	auditWriter.Write(entry, true)
}

func buildAlertGroupsQuery(r *http.Request, projectID uuid.UUID, limit, offset int) (*store.AlertGroupsQuery, error) {
	query, err := validateOptionalSearchQuery("q", r.URL.Query().Get("q"))
	if err != nil {
		return nil, err
	}
	q := &store.AlertGroupsQuery{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
		Query:     query,
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("severity")); raw != "" {
		q.Severities = parseSeverityList(raw)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("category")); raw != "" {
		q.Categories = parseCategoryListStrict(raw)
		if len(q.Categories) == 0 {
			return nil, store.ErrInvalidPayload
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("type")); raw != "" {
		q.Types = parseStringList(raw)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("status")); raw != "" {
		statuses := parseStringList(raw)
		for _, st := range statuses {
			normalized := store.AlertGroupStatus(strings.ToUpper(strings.TrimSpace(st)))
			switch normalized {
			case store.AlertGroupStatusOpen, store.AlertGroupStatusAcknowledged, store.AlertGroupStatusClosed:
				q.Status = append(q.Status, normalized)
			default:
				return nil, store.ErrInvalidPayload
			}
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("from")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			tt := t.UTC()
			q.From = &tt
		} else {
			return nil, err
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("to")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			tt := t.UTC()
			q.To = &tt
		} else {
			return nil, err
		}
	}
	q.OrderBySeen = strings.TrimSpace(r.URL.Query().Get("orderBy"))
	return q, nil
}

func buildAlertOccurrencesQuery(r *http.Request, projectID uuid.UUID, limit, offset int) (*store.AlertOccurrencesQuery, error) {
	query, err := validateOptionalSearchQuery("q", r.URL.Query().Get("q"))
	if err != nil {
		return nil, err
	}
	q := &store.AlertOccurrencesQuery{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
		Query:     query,
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("groupId")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, err
		}
		q.GroupID = &id
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("severity")); raw != "" {
		q.Severities = parseSeverityList(raw)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("category")); raw != "" {
		q.Categories = parseCategoryListStrict(raw)
		if len(q.Categories) == 0 {
			return nil, store.ErrInvalidPayload
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("type")); raw != "" {
		q.Types = parseStringList(raw)
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("from")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			tt := t.UTC()
			q.From = &tt
		} else {
			return nil, err
		}
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("to")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			tt := t.UTC()
			q.To = &tt
		} else {
			return nil, err
		}
	}
	return q, nil
}

func parseStringList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		t := sanitizePlainText(p)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func parseCategoryListStrict(raw string) []eventmeta.Category {
	parts := parseStringList(raw)
	out := make([]eventmeta.Category, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if !eventmeta.ValidCategory(p) {
			continue
		}
		out = append(out, eventmeta.Category(p))
	}
	return out
}
