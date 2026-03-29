package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

// ProblemDetails represents an RFC 7807 error response.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
	ErrorID  string `json:"errorId,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string, err error) {
	problem := ProblemDetails{
		Type:     "about:blank",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	}

	if status >= http.StatusInternalServerError {
		errorID := uuid.New().String()
		problem.ErrorID = errorID
		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		pattern := middleware.RoutePatternFromContext(r.Context())
		if err != nil {
			slog.Error(
				"request failed",
				"errorId", errorID,
				"trace_id", traceID,
				"component", component,
				"pattern", pattern,
				"error", audit.SanitizeLogValue(err.Error()),
			)
		} else {
			slog.Error(
				"request failed",
				"errorId", errorID,
				"trace_id", traceID,
				"component", component,
				"pattern", pattern,
			)
		}

		// Persist a high-signal api_error event to audit_logs for the Events UI.
		// Do not include raw server errors (PII/secrets risk); use errorId + traceId for correlation.
		if auditWriter := middleware.AuditWriterFromContext(r.Context()); auditWriter != nil {
			actorID := (*uuid.UUID)(nil)
			if userCtx, ok := auth.UserFromContext(r.Context()); ok && userCtx.ID != (uuid.UUID{}) {
				id := userCtx.ID
				actorID = &id
			}
			eventKey := strings.TrimSpace(component)
			if eventKey == "" {
				eventKey = "unknown"
			}
			eventKey = "api_error.http_5xx." + eventKey
			details, buildErr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryAPIError,
				Severity:  eventmeta.SeverityError,
				MinRole:   eventmeta.MinRoleWrite,
				EventKey:  eventKey,
				TraceID:   traceID,
				ErrorID:   errorID,
				Title:     "HTTP 5xx",
				Message:   "Request failed with a server error.",
				Component: component,
			}, map[string]any{
				"http_status": status,
				"method":      r.Method,
				"pattern":     pattern,
			})
			if buildErr == nil {
				entry := store.AuditLogEntry{
					ActorID:    actorID,
					Action:     "API_ERROR_5XX",
					EntityType: "API",
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}
				auditWriter.Write(entry, false)
			}
		}
	}

	writeJSON(w, status, problem)
}
