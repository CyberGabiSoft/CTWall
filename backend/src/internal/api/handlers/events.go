package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"
)

type eventsOpenCountResponse struct {
	Count int `json:"count"`
}

type eventsListResponse struct {
	Items      []store.EventAggregate `json:"items"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"pageSize"`
	Total      int                    `json:"total"`
	TotalPages int                    `json:"totalPages"`
}

type eventDetailsResponse struct {
	Event       store.EventAggregate `json:"event"`
	Occurrences []models.AuditLog    `json:"occurrences"`
}

func EventsOpenCountHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		q, err := buildEventsQueryFromRequest(r, userCtx, project.ID.String())
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
			return
		}
		// Badge shows open ERROR events by default.
		q.Severities = []eventmeta.Severity{eventmeta.SeverityError}
		q.CategoriesError = nil
		q.CategoriesWarn = nil
		q.CategoriesInfo = nil
		q.Status = store.EventsStatusOpen

		count, err := st.CountOpenEvents(q)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load open events count.", err)
			return
		}
		writeJSON(w, http.StatusOK, eventsOpenCountResponse{Count: count})
	}
}

func ListEventsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
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

		q, err := buildEventsQueryFromRequest(r, userCtx, project.ID.String())
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
			return
		}
		q.Limit = pageSize
		q.Offset = offset

		items, total, err := st.ListEvents(q)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid filters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list events.", err)
			return
		}
		totalPages := 1
		if pageSize > 0 {
			totalPages = (total + pageSize - 1) / pageSize
			if totalPages < 1 {
				totalPages = 1
			}
		}
		writeJSON(w, http.StatusOK, eventsListResponse{
			Items:      items,
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		})
	}
}

func GetEventHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		eventKey := strings.TrimSpace(r.PathValue("eventKey"))
		if eventKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid eventKey.", nil)
			return
		}

		q, err := buildEventsQueryFromRequest(r, userCtx, project.ID.String())
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid parameters.", err)
			return
		}
		// For details, allow all severities by default.
		q.Severities = []eventmeta.Severity{eventmeta.SeverityError, eventmeta.SeverityWarn, eventmeta.SeverityInfo}
		q.Status = "" // no status filter for details

		event, occurrences, err := st.GetEvent(eventKey, q, 20)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeProblem(w, r, http.StatusNotFound, "Not Found", "Event not found.", err)
				return
			}
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid parameters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load event details.", err)
			return
		}

		writeJSON(w, http.StatusOK, eventDetailsResponse{
			Event:       *event,
			Occurrences: occurrences,
		})
	}
}

func AckEventHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "Authentication required.", errors.New("missing user context"))
			return
		}
		if userCtx.Role != auth.RoleAdmin {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "Insufficient permissions.", nil)
			return
		}
		eventKey := strings.TrimSpace(r.PathValue("eventKey"))
		if eventKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid eventKey.", nil)
			return
		}
		if !eventmeta.ValidEventKey(eventKey) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid eventKey.", store.ErrInvalidPayload)
			return
		}
		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())

		details, err := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategorySystem,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  eventKey,
			TraceID:   traceID,
			Title:     "Event acknowledged",
			Message:   "Event acknowledged by admin.",
			Component: component,
		}, map[string]any{
			"acknowledged_at": time.Now().UTC(),
		})
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to acknowledge event.", err)
			return
		}

		entry := store.AuditLogEntry{
			ActorID:    &userCtx.ID,
			Action:     "EVENT_ACK",
			EntityType: "SYSTEM",
			Details:    details,
			IPAddress:  audit.IPFromRequest(r),
		}

		// Use audit writer if configured; otherwise fall back to direct store insert.
		if auditWriter != nil {
			auditWriter.Write(entry, true)
		} else if err := st.CreateAuditLog(entry); err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to acknowledge event.", err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func buildEventsQueryFromRequest(r *http.Request, userCtx auth.UserContext, projectID string) (store.EventsQuery, error) {
	categoriesError := parseCategoryList(r.URL.Query().Get("category_in_error"))
	categoriesWarn := parseCategoryList(r.URL.Query().Get("category_in_warn"))
	categoriesInfo := parseCategoryList(r.URL.Query().Get("category_in_info"))
	query, err := validateOptionalSearchQuery("q", r.URL.Query().Get("q"))
	if err != nil {
		return store.EventsQuery{}, err
	}

	q := store.EventsQuery{
		Severities:      parseSeverityList(r.URL.Query().Get("severity")),
		CategoriesError: categoriesError,
		CategoriesWarn:  categoriesWarn,
		CategoriesInfo:  categoriesInfo,
		Status:          store.EventsStatus(strings.TrimSpace(r.URL.Query().Get("status"))),
		Query:           query,
		ProjectID:       strings.TrimSpace(projectID),
	}

	switch userCtx.Role {
	case auth.RoleAdmin:
		q.ViewerRole = store.EventsViewerRoleAdmin
	case auth.RoleWriter:
		q.ViewerRole = store.EventsViewerRoleWrite
	default:
		q.ViewerRole = store.EventsViewerRoleRead
		q.ViewerID = userCtx.ID.String()
	}

	// Defaults: ERROR + open.
	if len(q.Severities) == 0 {
		q.Severities = []eventmeta.Severity{eventmeta.SeverityError}
	}
	if q.Status == "" {
		q.Status = store.EventsStatusOpen
	}

	// Optional time range.
	if fromRaw := strings.TrimSpace(r.URL.Query().Get("from")); fromRaw != "" {
		if parsed, err := time.Parse(time.RFC3339, fromRaw); err == nil {
			q.From = parsed.UTC()
		}
	}
	if toRaw := strings.TrimSpace(r.URL.Query().Get("to")); toRaw != "" {
		if parsed, err := time.Parse(time.RFC3339, toRaw); err == nil {
			q.To = parsed.UTC()
		}
	}

	q.NormalizeDefaults()
	return q, nil
}

func parseSeverityList(raw string) []eventmeta.Severity {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]eventmeta.Severity, 0, len(parts))
	for _, part := range parts {
		value := strings.ToUpper(strings.TrimSpace(part))
		if !eventmeta.ValidSeverity(value) {
			continue
		}
		out = append(out, eventmeta.Severity(value))
	}
	return out
}

func parseCategoryList(raw string) []eventmeta.Category {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]eventmeta.Category, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if !eventmeta.ValidCategory(value) {
			continue
		}
		out = append(out, eventmeta.Category(value))
	}
	return out
}
