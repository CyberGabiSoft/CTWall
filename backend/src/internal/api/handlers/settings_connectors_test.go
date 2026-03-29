package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"backend/internal/audit"
	"backend/internal/config"
	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func withUserContext(req *http.Request, projectID uuid.UUID, role auth.Role) *http.Request {
	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          uuid.New(),
		Email:       "admin@example.com",
		Role:        role,
		AccountType: auth.AccountTypeUser,
	})
	req = req.WithContext(ctx)
	req.Header.Set(projectHeaderName, projectID.String())
	return req
}

func withAdminContext(req *http.Request, projectID uuid.UUID) *http.Request {
	return withUserContext(req, projectID, auth.RoleAdmin)
}

func TestAdminSettingsGeneralHandler(t *testing.T) {
	cfg := config.Config{
		Server:   config.ServerConfig{Port: "8080"},
		Storage:  config.StorageConfig{Path: "data/blob"},
		Logging:  config.LoggingConfig{Level: "info"},
		Database: config.DatabaseConfig{PingTimeout: "5s"},
		Auth: config.AuthConfig{
			JWTIssuer: "ctwall-backend",
		},
	}
	handler := AdminSettingsGeneralHandler(cfg, "/etc/ctwall/config.yaml", map[string]string{
		"server.port":   "env",
		"storage.path":  "file",
		"logging.level": "file",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, uuid.New()))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload settingsGeneralResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.ConfigPath != "/etc/ctwall/config.yaml" {
		t.Fatalf("unexpected config path: %s", payload.ConfigPath)
	}
	if payload.Sources["server.port"] != "env" {
		t.Fatalf("expected env source for server.port")
	}
	if payload.Config.Server.Port != "8080" {
		t.Fatalf("unexpected config value: %s", payload.Config.Server.Port)
	}
}

func TestListAdminConnectorsHandler_Defaults(t *testing.T) {
	projectID := uuid.New()
	handler := ListAdminConnectorsHandler(tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/connectors", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload []connectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload) != len(store.AllMVPConnectorTypes()) {
		t.Fatalf("expected %d connectors, got %d", len(store.AllMVPConnectorTypes()), len(payload))
	}
	for _, row := range payload {
		if row.ScopeType != string(store.ConnectorScopeProject) {
			t.Fatalf("expected PROJECT scope, got %s", row.ScopeType)
		}
		if row.ScopeID != projectID.String() {
			t.Fatalf("expected project scope id, got %s", row.ScopeID)
		}
	}
}

func TestListAdminConnectorsHandler_ProjectAdminAccess(t *testing.T) {
	projectID := uuid.New()
	handler := ListAdminConnectorsHandler(tests.StoreWrapper{
		GetProjectItem:      &models.Project{ID: projectID, Name: "P1"},
		GetProjectRoleValue: store.ProjectRoleAdmin,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/connectors", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUserContext(req, projectID, auth.RoleNone))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for project admin, got %d", rec.Code)
	}
}

func TestListAdminConnectorsHandler_ReaderForbidden(t *testing.T) {
	projectID := uuid.New()
	handler := ListAdminConnectorsHandler(tests.StoreWrapper{
		GetProjectItem:      &models.Project{ID: projectID, Name: "P1"},
		GetProjectRoleValue: store.ProjectRoleReader,
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/connectors", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUserContext(req, projectID, auth.RoleNone))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for reader, got %d", rec.Code)
	}
}

func TestUpsertAdminConnectorHandler_MasksSecrets(t *testing.T) {
	projectID := uuid.New()
	now := time.Now().UTC()
	connectorID := uuid.New()
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		UpdatedProjectConnectorConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeJira,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     json.RawMessage(`{"baseUrl":"https://jira.local","apiToken":"super-secret"}`),
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestNotConfigured,
			CreatedAt:      now,
			UpdatedAt:      now,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := UpsertAdminConnectorHandler(wrapper, auditWriter)

	body := []byte(`{"enabled":true,"config":{"baseUrl":"https://jira.local","apiToken":"super-secret"}}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/connectors/jira", bytes.NewReader(body))
	req.SetPathValue("type", "jira")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload connectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Config["apiToken"] != "***" {
		t.Fatalf("expected masked token, got %#v", payload.Config["apiToken"])
	}
	if payload.Type != "jira" {
		t.Fatalf("unexpected type: %s", payload.Type)
	}
}

func TestPreserveConnectorSecrets_PreservesMaskedAndMissingValues(t *testing.T) {
	incoming := json.RawMessage(`{
		"base_url":"https://jira.example.local",
		"email":"admin@example.local",
		"api_token":"***"
	}`)
	existing := json.RawMessage(`{
		"base_url":"https://jira.example.local",
		"email":"admin@example.local",
		"api_token":"real-token"
	}`)

	merged := preserveConnectorSecrets(incoming, existing)
	var parsed map[string]any
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("decode merged config: %v", err)
	}
	if got := strings.TrimSpace(asString(parsed["api_token"])); got != "real-token" {
		t.Fatalf("expected preserved api_token, got %q", got)
	}

	incomingMissing := json.RawMessage(`{"base_url":"https://smtp.example.local","auth":"login"}`)
	existingMissing := json.RawMessage(`{"base_url":"https://smtp.example.local","auth":"login","password":"smtp-secret"}`)
	mergedMissing := preserveConnectorSecrets(incomingMissing, existingMissing)
	var parsedMissing map[string]any
	if err := json.Unmarshal(mergedMissing, &parsedMissing); err != nil {
		t.Fatalf("decode merged missing config: %v", err)
	}
	if got := strings.TrimSpace(asString(parsedMissing["password"])); got != "smtp-secret" {
		t.Fatalf("expected preserved missing password, got %q", got)
	}
}

func TestPreserveConnectorSecrets_DoesNotOverrideProvidedSecret(t *testing.T) {
	incoming := json.RawMessage(`{"api_token":"new-token"}`)
	existing := json.RawMessage(`{"api_token":"old-token"}`)
	merged := preserveConnectorSecrets(incoming, existing)

	var parsed map[string]any
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("decode merged config: %v", err)
	}
	if got := strings.TrimSpace(asString(parsed["api_token"])); got != "new-token" {
		t.Fatalf("expected new api_token to be kept, got %q", got)
	}
}

func TestParseConnectorTypePath_MVPDisabledTypesRejected(t *testing.T) {
	if _, err := parseConnectorTypePath("msteamsv2"); err == nil {
		t.Fatalf("expected msteamsv2 to be rejected in MVP")
	}
	if _, err := parseConnectorTypePath("webhook"); err == nil {
		t.Fatalf("expected webhook to be rejected in MVP")
	}
	if _, err := parseConnectorTypePath("jira"); err != nil {
		t.Fatalf("expected jira to remain enabled in MVP, got error: %v", err)
	}
}

func TestPreserveConnectorSecrets_MatchesKeyVariants(t *testing.T) {
	incoming := json.RawMessage(`{"apiToken":"***"}`)
	existing := json.RawMessage(`{"api_token":"real-token"}`)
	merged := preserveConnectorSecrets(incoming, existing)

	var parsed map[string]any
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("decode merged config: %v", err)
	}
	if got := strings.TrimSpace(asString(parsed["apiToken"])); got != "real-token" {
		t.Fatalf("expected preserved apiToken from api_token, got %q", got)
	}
}

func asString(value any) string {
	typed, _ := value.(string)
	return typed
}

func TestTestAdminConnectorHandler_FailedValidation(t *testing.T) {
	projectID := uuid.New()
	connectorID := uuid.New()
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		ProjectConnectorConfig: &store.ConnectorConfig{
			ID:            connectorID,
			ConnectorType: store.ConnectorTypeJira,
			ScopeType:     store.ConnectorScopeProject,
			ScopeID:       &projectID,
			ConfigJSON:    json.RawMessage(`{}`),
			IsEnabled:     true,
		},
		ProjectConnectorTestStatusConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeJira,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     json.RawMessage(`{}`),
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestFailed,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := TestAdminConnectorHandler(wrapper, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/connectors/jira/test", nil)
	req.SetPathValue("type", "jira")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload connectorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != store.ConnectorTestFailed {
		t.Fatalf("expected FAILED status, got %s", payload.Status)
	}
}

func TestTestAdminConnectorHandler_JiraRealOutboundCheck(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	projectID := uuid.New()
	connectorID := uuid.New()
	var gotPath string
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accountId":"abc"}`))
	}))
	defer srv.Close()

	cfgJSON := json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"super-secret",
		"requestTimeoutSeconds":10
	}`)
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		ProjectConnectorConfig: &store.ConnectorConfig{
			ID:            connectorID,
			ConnectorType: store.ConnectorTypeJira,
			ScopeType:     store.ConnectorScopeProject,
			ScopeID:       &projectID,
			ConfigJSON:    cfgJSON,
			IsEnabled:     true,
		},
		ProjectConnectorTestStatusConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeJira,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     cfgJSON,
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestPassed,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := TestAdminConnectorHandler(wrapper, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/connectors/jira/test", nil)
	req.SetPathValue("type", "jira")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if gotPath != "/rest/api/3/project/search" {
		t.Fatalf("unexpected jira test path: %s", gotPath)
	}
	if gotAuth == "" {
		t.Fatalf("expected authorization header for jira test request")
	}

	var payload connectorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != store.ConnectorTestPassed {
		t.Fatalf("expected PASSED status, got %s", payload.Status)
	}
	if payload.Message != "Jira test connection succeeded." {
		t.Fatalf("unexpected message: %s", payload.Message)
	}
}

func TestTestAdminConnectorHandler_SlackOutboundSend(t *testing.T) {
	projectID := uuid.New()
	var gotPath string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	connectorID := uuid.New()
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		ProjectConnectorConfig: &store.ConnectorConfig{
			ID:            connectorID,
			ConnectorType: store.ConnectorTypeSlack,
			ScopeType:     store.ConnectorScopeProject,
			ScopeID:       &projectID,
			ConfigJSON:    json.RawMessage(`{"webhookUrl":"` + srv.URL + `/hook","username":"CTWall Bot"}`),
			IsEnabled:     true,
		},
		ProjectConnectorTestStatusConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeSlack,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     json.RawMessage(`{"webhookUrl":"` + srv.URL + `/hook","username":"CTWall Bot"}`),
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestPassed,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := TestAdminConnectorHandler(wrapper, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/connectors/slack/test", nil)
	req.SetPathValue("type", "slack")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if gotPath != "/hook" {
		t.Fatalf("unexpected webhook path: %s", gotPath)
	}
	if gotPayload["text"] != "CTWall Slack connector test message." {
		t.Fatalf("unexpected slack text: %#v", gotPayload["text"])
	}

	var payload connectorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != store.ConnectorTestPassed {
		t.Fatalf("expected PASSED status, got %s", payload.Status)
	}
	if payload.Message != "Slack test message sent." {
		t.Fatalf("unexpected message: %s", payload.Message)
	}
}

func TestTestAdminConnectorHandler_DiscordOutboundSend(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	projectID := uuid.New()
	var gotPath string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	connectorID := uuid.New()
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		ProjectConnectorConfig: &store.ConnectorConfig{
			ID:            connectorID,
			ConnectorType: store.ConnectorTypeDiscord,
			ScopeType:     store.ConnectorScopeProject,
			ScopeID:       &projectID,
			ConfigJSON:    json.RawMessage(`{"webhookUrl":"` + srv.URL + `/discord"}`),
			IsEnabled:     true,
		},
		ProjectConnectorTestStatusConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeDiscord,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     json.RawMessage(`{"webhookUrl":"` + srv.URL + `/discord"}`),
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestPassed,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := TestAdminConnectorHandler(wrapper, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/connectors/discord/test", nil)
	req.SetPathValue("type", "discord")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if gotPath != "/discord" {
		t.Fatalf("unexpected webhook path: %s", gotPath)
	}
	if gotPayload["content"] != "CTWall Discord connector test message." {
		t.Fatalf("unexpected discord content: %#v", gotPayload["content"])
	}

	var payload connectorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != store.ConnectorTestPassed {
		t.Fatalf("expected PASSED status, got %s", payload.Status)
	}
	if payload.Message != "Discord test message sent." {
		t.Fatalf("unexpected message: %s", payload.Message)
	}
}

func TestTestAdminConnectorHandler_ExternalAlertmanagerConnection(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	projectID := uuid.New()
	connectorID := uuid.New()
	var readyCalls int
	var alertPosts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/ready" {
			readyCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/api/v2/alerts" && r.Method == http.MethodPost {
			alertPosts++
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	cfgJSON := json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"none",
		"timeoutSeconds":10
	}`)
	wrapper := tests.StoreWrapper{
		GetProjectItem: &models.Project{ID: projectID, Name: "P1"},
		ProjectConnectorConfig: &store.ConnectorConfig{
			ID:            connectorID,
			ConnectorType: store.ConnectorTypeAlertmanagerExternal,
			ScopeType:     store.ConnectorScopeProject,
			ScopeID:       &projectID,
			ConfigJSON:    cfgJSON,
			IsEnabled:     true,
		},
		ProjectConnectorTestStatusConfig: &store.ConnectorConfig{
			ID:             connectorID,
			ConnectorType:  store.ConnectorTypeAlertmanagerExternal,
			ScopeType:      store.ConnectorScopeProject,
			ScopeID:        &projectID,
			ConfigJSON:     cfgJSON,
			IsEnabled:      true,
			LastTestStatus: store.ConnectorTestPassed,
		},
	}
	auditWriter := audit.NewWriter(nil, audit.Config{}, slog.Default())
	handler := TestAdminConnectorHandler(wrapper, auditWriter)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/connectors/alertmanager_external/test", nil)
	req.SetPathValue("type", "alertmanager_external")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withAdminContext(req, projectID))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if readyCalls != 1 {
		t.Fatalf("expected one /-/ready request, got %d", readyCalls)
	}
	if alertPosts != 1 {
		t.Fatalf("expected one test alert POST, got %d", alertPosts)
	}

	var payload connectorTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != store.ConnectorTestPassed {
		t.Fatalf("expected PASSED status, got %s", payload.Status)
	}
	if payload.Message != "External Alertmanager health check succeeded and test alert sent." {
		t.Fatalf("unexpected message: %s", payload.Message)
	}
}

func TestEmitSMTPConnectorTestAlert(t *testing.T) {
	t.Run("posts alert with basic auth", func(t *testing.T) {
		var gotAuth string
		var gotPath string
		var gotMethod string
		var gotPayload []map[string]any

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotPath = r.URL.Path
			gotMethod = r.Method
			defer r.Body.Close()
			if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			w.WriteHeader(http.StatusAccepted)
		}))
		defer srv.Close()

		t.Setenv("ALERTMANAGER_URL", srv.URL)
		t.Setenv("ALERTMANAGER_USERNAME", "ctwall_backend")
		t.Setenv("ALERTMANAGER_PASSWORD", "secret")

		if err := emitSMTPConnectorTestAlert(t.Context(), "smtp-test@local.test"); err != nil {
			t.Fatalf("emit alert: %v", err)
		}
		if gotPath != "/api/v2/alerts" {
			t.Fatalf("unexpected path: %s", gotPath)
		}
		if gotMethod != http.MethodPost {
			t.Fatalf("unexpected method: %s", gotMethod)
		}
		if gotAuth == "" || !strings.HasPrefix(gotAuth, "Basic ") {
			t.Fatalf("expected basic auth header, got: %s", gotAuth)
		}
		if len(gotPayload) != 1 {
			t.Fatalf("expected one alert, got %d", len(gotPayload))
		}
		labels, _ := gotPayload[0]["labels"].(map[string]any)
		if labels["alertname"] != "CTWALL_SMTP_CONNECTOR_TEST" {
			t.Fatalf("unexpected alertname: %#v", labels["alertname"])
		}
	})

	t.Run("fails when alertmanager env missing", func(t *testing.T) {
		t.Setenv("ALERTMANAGER_URL", "")
		t.Setenv("ALERTMANAGER_USERNAME", "")
		t.Setenv("ALERTMANAGER_PASSWORD", "")
		if err := emitSMTPConnectorTestAlert(t.Context(), "smtp-test@local.test"); err == nil {
			t.Fatalf("expected missing configuration error")
		}
	})
}
