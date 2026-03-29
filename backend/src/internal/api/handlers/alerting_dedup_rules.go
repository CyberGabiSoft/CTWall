package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

const defaultAlertDedupRuleType = "malware.detected"

type alertDedupRuleResponse struct {
	Items []models.AlertDedupRule `json:"items"`
}

type alertDedupRuleInputPayload struct {
	DedupScope  string  `json:"dedupScope"`
	ProductID   *string `json:"productId,omitempty"`
	ScopeID     *string `json:"scopeId,omitempty"`
	TestID      *string `json:"testId,omitempty"`
	MinSeverity *string `json:"minSeverity,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type putAlertDedupRulesRequest struct {
	Rules []alertDedupRuleInputPayload `json:"rules"`
}

func ListAlertDedupRulesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		alertType := parseAlertDedupRuleType(r)
		items, err := st.ListAlertDedupRules(project.ID, alertType)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid dedup rule filters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list dedup rules.", err)
			return
		}
		if len(items) == 0 {
			// Keep default behavior visible in API/UI even when no explicit DB row exists.
			defaultScope := string(store.AlertDedupScopeGlobal)
			if strings.EqualFold(alertType, defaultAlertDedupRuleType) {
				defaultScope = string(store.AlertDedupScopeTest)
			}
			items = append(items, models.AlertDedupRule{
				ID:          uuid.Nil,
				ProjectID:   project.ID,
				AlertType:   alertType,
				DedupScope:  defaultScope,
				MinSeverity: string(store.AlertMinSeverityInfo),
				Enabled:     true,
			})
		}

		writeJSON(w, http.StatusOK, alertDedupRuleResponse{Items: items})
	}
}

func PutAlertDedupRulesHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, st, store.ProjectRoleWriter)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		alertType := parseAlertDedupRuleType(r)

		var req putAlertDedupRulesRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}

		inputs := make([]store.AlertDedupRuleInput, 0, len(req.Rules))
		for _, raw := range req.Rules {
			scope := strings.ToUpper(strings.TrimSpace(raw.DedupScope))
			if scope == "" {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "dedupScope is required.", nil)
				return
			}
			input := store.AlertDedupRuleInput{
				AlertType:   alertType,
				DedupScope:  store.AlertDedupScope(scope),
				MinSeverity: store.AlertMinSeverityInfo,
				Enabled:     true,
			}
			if raw.Enabled != nil {
				input.Enabled = *raw.Enabled
			}
			if raw.MinSeverity != nil {
				input.MinSeverity = store.AlertMinSeverity(strings.ToUpper(strings.TrimSpace(*raw.MinSeverity)))
			}

			if raw.ProductID != nil && strings.TrimSpace(*raw.ProductID) != "" {
				id, err := uuid.Parse(strings.TrimSpace(*raw.ProductID))
				if err != nil {
					writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productId.", err)
					return
				}
				input.ProductID = &id
			}
			if raw.ScopeID != nil && strings.TrimSpace(*raw.ScopeID) != "" {
				id, err := uuid.Parse(strings.TrimSpace(*raw.ScopeID))
				if err != nil {
					writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid scopeId.", err)
					return
				}
				input.ScopeID = &id
			}
			if raw.TestID != nil && strings.TrimSpace(*raw.TestID) != "" {
				id, err := uuid.Parse(strings.TrimSpace(*raw.TestID))
				if err != nil {
					writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId.", err)
					return
				}
				input.TestID = &id
			}
			inputs = append(inputs, input)
		}

		items, err := st.ReplaceAlertDedupRules(project.ID, alertType, inputs)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid dedup rules payload.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save dedup rules.", err)
			return
		}
		if strings.EqualFold(alertType, defaultAlertDedupRuleType) {
			if _, reconcileErr := st.ReconcileMalwareAlertGroupsForProject(project.ID, &userCtx.ID); reconcileErr != nil {
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to reconcile malware alerts after dedup rule update.", reconcileErr)
				return
			}
		}

		if auditWriter != nil {
			details, derr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryConfig,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleWrite,
				EventKey:  "alerts.dedup_rules.update",
				ProjectID: project.ID.String(),
				Title:     "Alert deduplication rules updated",
				Message:   "User updated alert deduplication rules.",
				Component: "handler.alerting.dedup_rules.put",
			}, map[string]any{
				"alertType":  alertType,
				"rulesCount": len(items),
			})
			if derr == nil {
				auditWriter.Write(store.AuditLogEntry{
					ActorID:    &userCtx.ID,
					Action:     "ALERT_DEDUP_RULES_UPDATE",
					EntityType: "alert_dedup_rule",
					EntityID:   nil,
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}, true)
			}
		}

		writeJSON(w, http.StatusOK, alertDedupRuleResponse{Items: items})
	}
}

func parseAlertDedupRuleType(r *http.Request) string {
	alertType := strings.TrimSpace(r.URL.Query().Get("alertType"))
	if alertType == "" {
		return defaultAlertDedupRuleType
	}
	return alertType
}
