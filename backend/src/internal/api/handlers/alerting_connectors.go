package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type alertingConnectorRouteSelection struct {
	ProductIDs []string `json:"productIds,omitempty"`
	ScopeIDs   []string `json:"scopeIds,omitempty"`
	TestIDs    []string `json:"testIds,omitempty"`
}

type alertingConnectorUpsertRequest struct {
	Enabled         bool                            `json:"enabled"`
	JiraDedupRuleID *string                         `json:"jiraDedupRuleId,omitempty"`
	Routes          alertingConnectorRouteSelection `json:"routes"`
}

type alertingConnectorConnectionStatus struct {
	Configured        bool                      `json:"configured"`
	ConnectionEnabled bool                      `json:"connectionEnabled"`
	LastTestStatus    store.ConnectorTestStatus `json:"lastTestStatus"`
	LastTestAt        *string                   `json:"lastTestAt,omitempty"`
	LastTestMessage   string                    `json:"lastTestMessage,omitempty"`
}

type alertingConnectorStateResponse struct {
	Type             string                            `json:"type"`
	ProjectID        string                            `json:"projectId"`
	AlertingEnabled  bool                              `json:"alertingEnabled"`
	JiraDedupRuleID  *string                           `json:"jiraDedupRuleId,omitempty"`
	Routes           []store.AlertRouteRef             `json:"routes"`
	ConnectionStatus alertingConnectorConnectionStatus `json:"connectionStatus"`
}

// GetAlertingConnectorsHandler returns per-project routing state and read-only connection status (no secrets).
func GetAlertingConnectorsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		settings, err := st.GetAlertConnectorSettings(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load alerting settings.", err)
			return
		}

		byType := make(map[store.ConnectorType]store.AlertConnectorSettings, len(settings))
		for _, s := range settings {
			byType[s.ConnectorType] = s
		}

		out := make([]alertingConnectorStateResponse, 0, len(store.AllMVPConnectorTypes()))
		for _, ct := range store.AllMVPConnectorTypes() {
			state, ok := byType[ct]
			if !ok {
				state = store.AlertConnectorSettings{
					ProjectID:     project.ID,
					ConnectorType: ct,
					IsEnabled:     false,
					Routes:        nil,
				}
			}

			conn := alertingConnectorConnectionStatus{
				Configured:        false,
				ConnectionEnabled: false,
				LastTestStatus:    store.ConnectorTestNotConfigured,
			}
			if cfg, err := st.GetProjectConnectorConfig(project.ID, ct); err == nil && cfg != nil {
				conn.Configured = len(strings.TrimSpace(string(cfg.ConfigJSON))) > 2
				conn.ConnectionEnabled = cfg.IsEnabled
				conn.LastTestStatus = cfg.LastTestStatus
				if cfg.LastTestAt != nil {
					ts := cfg.LastTestAt.UTC().Format(timeRFC3339())
					conn.LastTestAt = &ts
				}
				conn.LastTestMessage = cfg.LastTestMessage
			}

			out = append(out, alertingConnectorStateResponse{
				Type:             strings.ToLower(string(ct)),
				ProjectID:        project.ID.String(),
				AlertingEnabled:  state.IsEnabled,
				JiraDedupRuleID:  uuidPtrString(state.JiraDedupRuleID),
				Routes:           state.Routes,
				ConnectionStatus: conn,
			})
		}

		writeJSON(w, http.StatusOK, out)
	}
}

func timeRFC3339() string {
	// Small helper to keep imports minimal; handlers already use RFC3339 widely.
	return "2006-01-02T15:04:05Z07:00"
}

// UpsertAlertingConnectorHandler updates per-project alerting routing.
// Admin-only.
func UpsertAlertingConnectorHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, st, store.ProjectRoleAdmin)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		ct, err := parseAlertingConnectorType(r.PathValue("type"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Unsupported connector type.", err)
			return
		}

		var req alertingConnectorUpsertRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}

		productIDs, err := parseUUIDList(req.Routes.ProductIDs)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productIds.", err)
			return
		}
		scopeIDs, err := parseUUIDList(req.Routes.ScopeIDs)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid scopeIds.", err)
			return
		}
		testIDs, err := parseUUIDList(req.Routes.TestIDs)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testIds.", err)
			return
		}
		var jiraDedupRuleID *uuid.UUID
		if ct == store.ConnectorTypeJira {
			jiraDedupRuleID, err = parseOptionalUUID(req.JiraDedupRuleID)
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid jiraDedupRuleId.", err)
				return
			}
			if req.Enabled && jiraDedupRuleID == nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "jiraDedupRuleId is required for enabled Jira alert routing.", nil)
				return
			}
		}

		// Validate targets belong to project (no cross-project routing injection).
		if err := st.ValidateAlertRouteTargets(project.ID, store.AlertRouteTargetProduct, productIDs); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productIds selection.", err)
			return
		}
		if err := st.ValidateAlertRouteTargets(project.ID, store.AlertRouteTargetScope, scopeIDs); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid scopeIds selection.", err)
			return
		}
		if err := st.ValidateAlertRouteTargets(project.ID, store.AlertRouteTargetTest, testIDs); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testIds selection.", err)
			return
		}

		routes := make([]store.AlertRouteRef, 0, len(productIDs)+len(scopeIDs)+len(testIDs))
		for _, id := range productIDs {
			routes = append(routes, store.AlertRouteRef{TargetType: store.AlertRouteTargetProduct, TargetID: id})
		}
		for _, id := range scopeIDs {
			routes = append(routes, store.AlertRouteRef{TargetType: store.AlertRouteTargetScope, TargetID: id})
		}
		for _, id := range testIDs {
			routes = append(routes, store.AlertRouteRef{TargetType: store.AlertRouteTargetTest, TargetID: id})
		}

		item, err := st.UpsertAlertConnectorSettings(project.ID, ct, req.Enabled, routes)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid routing payload.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save alerting routing.", err)
			return
		}
		if ct == store.ConnectorTypeJira {
			updated, err := st.SetAlertConnectorJiraDedupRule(project.ID, jiraDedupRuleID)
			if err != nil {
				if errors.Is(err, store.ErrInvalidPayload) {
					writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid Jira dedup-rule binding.", err)
					return
				}
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save Jira dedup-rule binding.", err)
				return
			}
			item.JiraDedupRuleID = updated.JiraDedupRuleID
		}
		if _, enqueueErr := st.EnqueueAlertDispatchJob(store.AlertDispatchEnqueueInput{
			MessageType: store.AlertDispatchMessageTypeConfigApply,
			PayloadJSON: json.RawMessage(fmt.Sprintf(`{"reason":"alerting_routing_update","projectId":"%s","connectorType":"%s"}`, project.ID.String(), strings.ToLower(string(ct)))),
		}); enqueueErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to enqueue alertmanager config apply.", enqueueErr)
			return
		}

		// Audit routing update (append-only).
		if auditWriter != nil {
			details, derr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryConfig,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleAdmin,
				EventKey:  "alerts.routing.update",
				ProjectID: project.ID.String(),
				Title:     "Alerting routing updated",
				Message:   "Admin updated alerting connector routing.",
				Component: "handler.alerting.connectors.upsert",
			}, map[string]any{
				"connectorType":   strings.ToLower(string(ct)),
				"enabled":         item.IsEnabled,
				"jiraDedupRuleId": uuidPtrString(item.JiraDedupRuleID),
				"routesCount":     len(item.Routes),
			})
			if derr == nil {
				auditWriter.Write(store.AuditLogEntry{
					ActorID:    &userCtx.ID,
					Action:     "ALERT_ROUTING_UPDATE",
					EntityType: "alert_routing",
					EntityID:   nil,
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}, true)
			}
		}

		writeJSON(w, http.StatusOK, item)
	}
}

func parseOptionalUUID(raw *string) (*uuid.UUID, error) {
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*raw)
	if trimmed == "" {
		return nil, nil
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		return nil, err
	}
	if parsed == uuid.Nil {
		return nil, nil
	}
	return &parsed, nil
}

func uuidPtrString(id *uuid.UUID) *string {
	if id == nil || *id == uuid.Nil {
		return nil
	}
	value := id.String()
	return &value
}

func parseAlertingConnectorType(raw string) (store.ConnectorType, error) {
	ct := store.NormalizeConnectorType(raw)
	if !store.ValidConnectorType(ct) || !store.IsConnectorTypeEnabledInMVP(ct) {
		return "", errors.New("unsupported connector type")
	}
	return ct, nil
}

func parseUUIDList(raw []string) ([]uuid.UUID, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]uuid.UUID, 0, len(raw))
	seen := make(map[uuid.UUID]struct{}, len(raw))
	for _, v := range raw {
		id, err := uuid.Parse(strings.TrimSpace(v))
		if err != nil {
			return nil, err
		}
		if id == uuid.Nil {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}
