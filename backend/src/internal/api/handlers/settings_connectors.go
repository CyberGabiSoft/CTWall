package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/core/alerting"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type connectorUpsertRequest struct {
	Enabled bool            `json:"enabled"`
	Config  json.RawMessage `json:"config"`
}

type connectorResponse struct {
	ID              string                    `json:"id,omitempty"`
	Type            string                    `json:"type"`
	ScopeType       string                    `json:"scopeType"`
	ScopeID         string                    `json:"scopeId,omitempty"`
	Enabled         bool                      `json:"enabled"`
	Configured      bool                      `json:"configured"`
	Config          map[string]any            `json:"config"`
	LastTestStatus  store.ConnectorTestStatus `json:"lastTestStatus"`
	LastTestAt      *time.Time                `json:"lastTestAt,omitempty"`
	LastTestMessage string                    `json:"lastTestMessage,omitempty"`
	UpdatedAt       *time.Time                `json:"updatedAt,omitempty"`
}

type connectorTestResponse struct {
	Type     string                    `json:"type"`
	Status   store.ConnectorTestStatus `json:"status"`
	Message  string                    `json:"message"`
	TestedAt time.Time                 `json:"testedAt"`
}

type smtpTestRequest struct {
	ToEmail string `json:"toEmail,omitempty"`
}

func requireConnectorManagePermission(userCtx auth.UserContext, st store.Store, projectID uuid.UUID) *resolveError {
	if isAdminRole(userCtx.Role) {
		return nil
	}
	return requireProjectRole(userCtx, st, projectID, store.ProjectRoleAdmin)
}

// ListAdminConnectorsHandler returns all supported connector configs in active PROJECT scope.
func ListAdminConnectorsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireConnectorManagePermission(userCtx, st, project.ID); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		items, err := st.ListProjectConnectorConfigs(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list connectors.", err)
			return
		}
		byType := make(map[store.ConnectorType]store.ConnectorConfig, len(items))
		for _, item := range items {
			byType[item.ConnectorType] = item
		}
		response := make([]connectorResponse, 0, len(store.AllMVPConnectorTypes()))
		for _, connectorType := range store.AllMVPConnectorTypes() {
			item, ok := byType[connectorType]
			if !ok {
				response = append(response, connectorResponse{
					Type:           toConnectorAPIType(connectorType),
					ScopeType:      string(store.ConnectorScopeProject),
					ScopeID:        project.ID.String(),
					Enabled:        false,
					Configured:     false,
					Config:         map[string]any{},
					LastTestStatus: store.ConnectorTestNotConfigured,
				})
				continue
			}
			response = append(response, mapConnectorResponse(item))
		}
		writeJSON(w, http.StatusOK, response)
	}
}

// UpsertAdminConnectorHandler creates/updates PROJECT connector config.
func UpsertAdminConnectorHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireConnectorManagePermission(userCtx, st, project.ID); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		connectorType, err := parseConnectorTypePath(r.PathValue("type"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Unsupported connector type.", err)
			return
		}

		var req connectorUpsertRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		configJSON, err := normalizeConnectorRequestConfig(req.Config)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		existing, existingErr := st.GetProjectConnectorConfig(project.ID, connectorType)
		if existingErr != nil && !errors.Is(existingErr, store.ErrNotFound) {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load existing connector config.", existingErr)
			return
		}
		if existing != nil {
			configJSON = preserveConnectorSecrets(configJSON, existing.ConfigJSON)
		}

		item, err := st.UpsertProjectConnectorConfig(project.ID, connectorType, configJSON, req.Enabled)
		if err == store.ErrInvalidPayload {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid connector payload.", nil)
			return
		}
		if err != nil && strings.Contains(strings.ToUpper(err.Error()), "APP_ENCRYPTION_KEY") {
			writeProblem(w, r, http.StatusInternalServerError, "Configuration Error", "Connector secret encryption key is not configured correctly.", err)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save connector config.", err)
			return
		}
		if _, enqueueErr := st.EnqueueAlertDispatchJob(store.AlertDispatchEnqueueInput{
			MessageType: store.AlertDispatchMessageTypeConfigApply,
			PayloadJSON: json.RawMessage(fmt.Sprintf(`{"reason":"project_connector_update","projectId":"%s","connectorType":"%s"}`, project.ID.String(), toConnectorAPIType(connectorType))),
		}); enqueueErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to enqueue alertmanager config apply.", enqueueErr)
			return
		}

		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		eventKey := connectorUpdateAuditEventKey(connectorType)
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryConfig,
			Severity:  eventmeta.SeverityInfo,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  eventKey,
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Connector updated",
			Message:   "Connector settings updated for project.",
			Component: component,
		}, map[string]any{
			"connectorType": toConnectorAPIType(connectorType),
			"enabled":       item.IsEnabled,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "CONNECTOR_UPDATE",
				EntityType: "CONNECTOR",
				EntityID:   &item.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		writeJSON(w, http.StatusOK, mapConnectorResponse(*item))
	}
}

// TestAdminConnectorHandler validates connector config and records last test status.
// SMTP, Slack and Discord perform direct outbound sends (admin-only) to validate connector credentials and reachability.
// Jira performs a non-mutating real API connectivity/auth test.
func TestAdminConnectorHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		if authzErr := requireConnectorManagePermission(userCtx, st, project.ID); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}
		connectorType, err := parseConnectorTypePath(r.PathValue("type"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Unsupported connector type.", err)
			return
		}
		item, err := st.GetProjectConnectorConfig(project.ID, connectorType)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Connector is not configured.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load connector config.", err)
			return
		}

		status := store.ConnectorTestPassed
		message := "Connector configuration validated (MVP validation-only test)."

		// SMTP is special-cased: perform a real send test (admin-only) with strict timeouts.
		// After successful send we also emit a synthetic test alert to Alertmanager.
		if connectorType == store.ConnectorTypeSMTP {
			toEmail := strings.TrimSpace(userCtx.Email)
			var payload smtpTestRequest
			if err := decodeOptionalJSON(r, &payload); err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
				return
			}
			if strings.TrimSpace(payload.ToEmail) != "" {
				toEmail = strings.TrimSpace(payload.ToEmail)
			}
			toEmail, err = validateEmail("toEmail", toEmail, true)
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid toEmail for SMTP test.", err)
				return
			}

			cfg, err := alerting.ParseSMTPConfig(item.ConfigJSON)
			if err != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(err.Error())
			} else {
				ctx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.TimeoutSeconds)*time.Second)
				defer cancel()
				if err := alerting.SendSMTP(ctx, cfg, alerting.SendEmailRequest{
					ToEmail: toEmail,
					Subject: "CTWall SMTP connector test",
					Body:    "This is a test message sent by CTWall to validate SMTP connector configuration.",
				}); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(err.Error())
				} else {
					if err := emitSMTPConnectorTestAlert(r.Context(), toEmail); err != nil {
						status = store.ConnectorTestFailed
						message = sanitizePlainText(fmt.Sprintf("SMTP test email sent, but failed to publish Alertmanager test alert: %v", err))
					} else {
						status = store.ConnectorTestPassed
						message = "SMTP test email sent and Alertmanager test alert published."
					}
				}
			}
		} else if connectorType == store.ConnectorTypeSlack {
			cfg, err := alerting.ParseSlackConfig(item.ConfigJSON)
			if err != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(err.Error())
			} else {
				if err := alerting.SendSlack(r.Context(), cfg, alerting.SendSlackRequest{
					Text: "CTWall Slack connector test message.",
				}); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(err.Error())
				} else {
					status = store.ConnectorTestPassed
					message = "Slack test message sent."
				}
			}
		} else if connectorType == store.ConnectorTypeDiscord {
			cfg, err := alerting.ParseDiscordConfig(item.ConfigJSON)
			if err != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(err.Error())
			} else {
				if err := alerting.SendDiscord(r.Context(), cfg, alerting.SendDiscordRequest{
					Content: "CTWall Discord connector test message.",
				}); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(err.Error())
				} else {
					status = store.ConnectorTestPassed
					message = "Discord test message sent."
				}
			}
		} else if connectorType == store.ConnectorTypeJira {
			cfg, err := alerting.ParseJiraConnectorProfile(item.ConfigJSON)
			if err != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(err.Error())
			} else {
				testCtx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.RequestTimeoutSeconds)*time.Second)
				defer cancel()
				if err := alerting.TestJiraConnection(testCtx, cfg); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(err.Error())
				} else {
					status = store.ConnectorTestPassed
					message = "Jira test connection succeeded."
				}
			}
		} else if connectorType == store.ConnectorTypeAlertmanagerExternal {
			cfg, err := alerting.ParseExternalAlertmanagerConnectorConfig(item.ConfigJSON)
			if err != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(err.Error())
			} else {
				testCtx, cancel := context.WithTimeout(r.Context(), time.Duration(cfg.TimeoutSeconds)*time.Second)
				defer cancel()
				if err := alerting.TestExternalAlertmanagerConnection(testCtx, cfg); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(err.Error())
				} else if err := alerting.SendExternalAlertmanagerTestAlert(testCtx, cfg); err != nil {
					status = store.ConnectorTestFailed
					message = sanitizePlainText(fmt.Sprintf("External Alertmanager health check succeeded, but sending test alert failed: %v", err))
				} else {
					status = store.ConnectorTestPassed
					message = "External Alertmanager health check succeeded and test alert sent."
				}
			}
		} else {
			if validationErr := validateConnectorConfig(connectorType, item.ConfigJSON); validationErr != nil {
				status = store.ConnectorTestFailed
				message = sanitizePlainText(validationErr.Error())
			}
		}

		testedAt := time.Now().UTC()
		updated, err := st.UpdateProjectConnectorTestStatus(project.ID, connectorType, status, message, testedAt)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Connector is not configured.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save connector test result.", err)
			return
		}

		severity := eventmeta.SeverityInfo
		if status == store.ConnectorTestFailed {
			severity = eventmeta.SeverityWarn
		}
		eventKey := connectorTestAuditEventKey(connectorType)
		traceID := middleware.TraceIDFromContext(r.Context())
		component := middleware.ComponentFromContext(r.Context())
		details, detailsErr := audit.BuildDetails(audit.DetailsBase{
			Category:  eventmeta.CategoryConfig,
			Severity:  severity,
			MinRole:   eventmeta.MinRoleAdmin,
			EventKey:  eventKey,
			ProjectID: project.ID.String(),
			TraceID:   traceID,
			Title:     "Connector test executed",
			Message:   "Connector configuration test executed.",
			Component: component,
		}, map[string]any{
			"connectorType": toConnectorAPIType(connectorType),
			"status":        string(status),
			"resultMessage": message,
		})
		if detailsErr == nil {
			entry := store.AuditLogEntry{
				ActorID:    &userCtx.ID,
				Action:     "CONNECTOR_TEST_CONNECTION",
				EntityType: "CONNECTOR",
				EntityID:   &updated.ID,
				Details:    details,
				IPAddress:  audit.IPFromRequest(r),
			}
			if auditWriter != nil {
				auditWriter.Write(entry, true)
			} else {
				_ = st.CreateAuditLog(entry)
			}
		}

		writeJSON(w, http.StatusOK, connectorTestResponse{
			Type:     toConnectorAPIType(connectorType),
			Status:   status,
			Message:  message,
			TestedAt: testedAt,
		})
	}
}

func parseConnectorTypePath(raw string) (store.ConnectorType, error) {
	connectorType := store.NormalizeConnectorType(raw)
	if !store.ValidConnectorType(connectorType) || !store.IsConnectorTypeEnabledInMVP(connectorType) {
		return "", fmt.Errorf("invalid connector type")
	}
	return connectorType, nil
}

func normalizeConnectorRequestConfig(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid([]byte(trimmed)) {
		return nil, fmt.Errorf("field 'config' must be valid JSON")
	}
	if !strings.HasPrefix(trimmed, "{") {
		return nil, fmt.Errorf("field 'config' must be a JSON object")
	}
	return json.RawMessage(trimmed), nil
}

func preserveConnectorSecrets(incomingRaw json.RawMessage, existingRaw json.RawMessage) json.RawMessage {
	var incoming map[string]any
	if err := json.Unmarshal(incomingRaw, &incoming); err != nil || incoming == nil {
		return incomingRaw
	}
	var existing map[string]any
	if err := json.Unmarshal(existingRaw, &existing); err != nil || existing == nil {
		return incomingRaw
	}

	incomingByNormalized := make(map[string]string, len(incoming))
	for key := range incoming {
		incomingByNormalized[normalizeConnectorKey(key)] = key
	}

	for existingKey, existingValue := range existing {
		normalizedKey := normalizeConnectorKey(existingKey)
		if !isSensitiveConnectorKey(normalizedKey) {
			continue
		}
		existingSecret, ok := existingValue.(string)
		if !ok {
			continue
		}
		existingSecret = strings.TrimSpace(existingSecret)
		if existingSecret == "" || existingSecret == "***" {
			continue
		}

		if incomingKey, exists := incomingByNormalized[normalizedKey]; exists {
			typed, ok := incoming[incomingKey].(string)
			if !ok {
				continue
			}
			typed = strings.TrimSpace(typed)
			if typed == "" || typed == "***" {
				incoming[incomingKey] = existingSecret
			}
			continue
		}

		incoming[existingKey] = existingSecret
	}

	merged, err := json.Marshal(incoming)
	if err != nil {
		return incomingRaw
	}
	return json.RawMessage(merged)
}

func normalizeConnectorKey(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(strings.ReplaceAll(trimmed, "-", "_"), " ", "_")
	var builder strings.Builder
	builder.Grow(len(trimmed) + 4)
	for idx, ch := range trimmed {
		if ch >= 'A' && ch <= 'Z' {
			if idx > 0 {
				prev := rune(trimmed[idx-1])
				if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
					builder.WriteByte('_')
				}
			}
			builder.WriteRune(ch + ('a' - 'A'))
			continue
		}
		builder.WriteRune(ch)
	}
	return builder.String()
}

func validateConnectorConfig(connectorType store.ConnectorType, raw json.RawMessage) error {
	if connectorType == store.ConnectorTypeJira {
		_, err := alerting.ParseJiraConnectorProfile(raw)
		return err
	}
	return alerting.ValidateAlertmanagerConnectorConfig(connectorType, raw)
}

func emitSMTPConnectorTestAlert(ctx context.Context, toEmail string) error {
	alertmanagerURL := strings.TrimSpace(os.Getenv("ALERTMANAGER_URL"))
	if alertmanagerURL == "" {
		return fmt.Errorf("ALERTMANAGER_URL is required")
	}
	username := strings.TrimSpace(os.Getenv("ALERTMANAGER_USERNAME"))
	password := strings.TrimSpace(os.Getenv("ALERTMANAGER_PASSWORD"))
	if username == "" || password == "" {
		return fmt.Errorf("ALERTMANAGER_USERNAME and ALERTMANAGER_PASSWORD are required")
	}

	client, err := alerting.NewAlertmanagerClient(alertmanagerURL, username, password, 10*time.Second)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	annotations := map[string]string{
		"title":       "CTWall SMTP connector test",
		"description": "SMTP connector test succeeded and emitted a synthetic test alert.",
	}
	if value := strings.TrimSpace(toEmail); value != "" {
		annotations["to_email"] = value
	}
	payload := alerting.AlertmanagerAlert{
		Labels: map[string]string{
			"alertname":      "CTWALL_SMTP_CONNECTOR_TEST",
			"severity":       "INFO",
			"category":       "CONFIG",
			"connector_type": "smtp",
			"event_state":    "TEST",
		},
		Annotations: annotations,
		StartsAt:    now.Format(time.RFC3339),
		EndsAt:      now.Add(2 * time.Minute).Format(time.RFC3339),
	}

	sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return client.PostAlerts(sendCtx, []alerting.AlertmanagerAlert{payload})
}

func mapConnectorResponse(item store.ConnectorConfig) connectorResponse {
	response := connectorResponse{
		ID:              item.ID.String(),
		Type:            toConnectorAPIType(item.ConnectorType),
		ScopeType:       string(item.ScopeType),
		Enabled:         item.IsEnabled,
		Configured:      len(strings.TrimSpace(string(item.ConfigJSON))) > 2,
		Config:          sanitizeConnectorConfigForRead(item.ConfigJSON),
		LastTestStatus:  item.LastTestStatus,
		LastTestAt:      item.LastTestAt,
		LastTestMessage: item.LastTestMessage,
	}
	if item.ScopeID != nil {
		response.ScopeID = item.ScopeID.String()
	}
	if !item.UpdatedAt.IsZero() {
		updated := item.UpdatedAt
		response.UpdatedAt = &updated
	}
	return response
}

func toConnectorAPIType(connectorType store.ConnectorType) string {
	switch connectorType {
	case store.ConnectorTypeDiscord:
		return "discord"
	case store.ConnectorTypeMSTeamsV2:
		return "msteamsv2"
	case store.ConnectorTypeJira:
		return "jira"
	case store.ConnectorTypeAlertmanagerExternal:
		return "alertmanager_external"
	case store.ConnectorTypeOpsgenie:
		return "opsgenie"
	case store.ConnectorTypePagerDuty:
		return "pagerduty"
	case store.ConnectorTypePushover:
		return "pushover"
	case store.ConnectorTypeRocketChat:
		return "rocketchat"
	case store.ConnectorTypeSlack:
		return "slack"
	case store.ConnectorTypeSNS:
		return "sns"
	case store.ConnectorTypeSMTP:
		return "smtp"
	case store.ConnectorTypeTelegram:
		return "telegram"
	case store.ConnectorTypeVictorOps:
		return "victorops"
	case store.ConnectorTypeWebex:
		return "webex"
	case store.ConnectorTypeWebhook:
		return "webhook"
	case store.ConnectorTypeWeChat:
		return "wechat"
	default:
		return strings.ToLower(string(connectorType))
	}
}

func connectorUpdateAuditEventKey(connectorType store.ConnectorType) string {
	switch connectorType {
	case store.ConnectorTypeAlertmanagerExternal:
		return "config.connector.alertmanager_external.update"
	default:
		return "config.connector.update"
	}
}

func connectorTestAuditEventKey(connectorType store.ConnectorType) string {
	switch connectorType {
	case store.ConnectorTypeJira:
		return "config.connector.jira.test_connection"
	case store.ConnectorTypeAlertmanagerExternal:
		return "config.connector.alertmanager_external.test_connection"
	default:
		return "config.connector.test_connection"
	}
}

func sanitizeConnectorConfigForRead(raw json.RawMessage) map[string]any {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return map[string]any{}
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return map[string]any{}
	}
	sanitizeConfigMap(cfg)
	return cfg
}

func sanitizeConfigMap(cfg map[string]any) {
	for key, value := range cfg {
		cleanKey := strings.ToLower(strings.TrimSpace(key))
		if isSensitiveConnectorKey(cleanKey) {
			cfg[key] = "***"
			continue
		}
		switch typed := value.(type) {
		case map[string]any:
			sanitizeConfigMap(typed)
		case []any:
			for idx := range typed {
				if nested, ok := typed[idx].(map[string]any); ok {
					sanitizeConfigMap(nested)
				}
			}
		}
	}
}

func isSensitiveConnectorKey(key string) bool {
	if key == "" {
		return false
	}
	switch {
	case strings.Contains(key, "token"):
		return true
	case strings.Contains(key, "password"):
		return true
	case strings.Contains(key, "secret"):
		return true
	case key == "apikey" || key == "api_key":
		return true
	case strings.Contains(key, "webhook"):
		return true
	default:
		return false
	}
}
