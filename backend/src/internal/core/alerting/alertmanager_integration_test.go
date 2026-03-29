package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"backend/internal/store"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"
)

type renderStoreStub struct {
	store.Store
	enabledProjects   map[store.ConnectorType][]uuid.UUID
	projectConnectors map[string]*store.ConnectorConfig
	projectEmails     map[uuid.UUID][]string
}

func connectorKey(projectID uuid.UUID, connectorType store.ConnectorType) string {
	return projectID.String() + "::" + string(connectorType)
}

func (s renderStoreStub) ListEnabledAlertProjects(connectorType store.ConnectorType) ([]uuid.UUID, error) {
	return append([]uuid.UUID(nil), s.enabledProjects[connectorType]...), nil
}

func (s renderStoreStub) GetProjectConnectorConfig(projectID uuid.UUID, connectorType store.ConnectorType) (*store.ConnectorConfig, error) {
	item := s.projectConnectors[connectorKey(projectID, connectorType)]
	if item == nil {
		return nil, store.ErrNotFound
	}
	return item, nil
}

func (s renderStoreStub) ListProjectAdminEmails(projectID uuid.UUID) ([]string, error) {
	return append([]string(nil), s.projectEmails[projectID]...), nil
}

func findRouteByMatchers(routes []alertmanagerRoute, matcherA, matcherB string) *alertmanagerRoute {
	for i := range routes {
		hasA := false
		hasB := false
		for _, matcher := range routes[i].Matchers {
			if matcher == matcherA {
				hasA = true
			}
			if matcher == matcherB {
				hasB = true
			}
		}
		if hasA && hasB {
			return &routes[i]
		}
	}
	return nil
}

func TestRenderAlertmanagerYAML_SMTPStartTLSPort587(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeSMTP: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSMTP): {
				ConnectorType: store.ConnectorTypeSMTP,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"host":"smtp.example.local",
					"port":587,
					"username":"mailer",
					"password":"secret",
					"auth":"plain",
					"authIdentity":"relay-id",
					"fromEmail":"alerts@example.local",
					"fromName":"CTWall Alerts",
					"replyTo":"noreply@example.local",
					"domain":"ctwall.local",
					"encryption":"starttls",
					"verifyMode":"peer",
					"caFile":"/etc/ssl/certs/custom-ca.pem",
					"serverName":"smtp.example.local"
				}`),
			},
		},
		projectEmails: map[uuid.UUID][]string{projectID: {"admin@example.local"}},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if len(cfg.Receivers) < 2 {
		t.Fatalf("expected blackhole + smtp receiver, got %d", len(cfg.Receivers))
	}
	smtpMatcherA := fmt.Sprintf(`project_id="%s"`, projectID.String())
	smtpMatcherB := `connector_type="smtp"`
	route := findRouteByMatchers(cfg.Route.Routes, smtpMatcherA, smtpMatcherB)
	if route == nil {
		t.Fatalf("expected route with smtp/project matchers, got %#v", cfg.Route.Routes)
	}
	var smtpReceiver *alertmanagerReceiver
	for i := range cfg.Receivers {
		if cfg.Receivers[i].Name == route.Receiver {
			smtpReceiver = &cfg.Receivers[i]
			break
		}
	}
	if smtpReceiver == nil || len(smtpReceiver.EmailConfigs) != 1 {
		t.Fatalf("expected smtp receiver with one email config")
	}
	email := smtpReceiver.EmailConfigs[0]
	if email["to"] != "admin@example.local" {
		t.Fatalf("unexpected smtp to: %#v", email["to"])
	}
	if email["smarthost"] != "smtp.example.local:587" {
		t.Fatalf("unexpected smarthost: %#v", email["smarthost"])
	}
	if email["hello"] != "ctwall.local" {
		t.Fatalf("unexpected smtp hello: %#v", email["hello"])
	}
	if email["require_tls"] != true {
		t.Fatalf("expected require_tls=true for 587/starttls")
	}
	headers, _ := email["headers"].(map[string]any)
	if headers["Reply-To"] != "noreply@example.local" {
		t.Fatalf("expected Reply-To header, got %#v", headers)
	}
}

func TestRenderAlertmanagerYAML_SMTPTLSWrapperPort465(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeSMTP: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSMTP): {
				ConnectorType: store.ConnectorTypeSMTP,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"host":"smtp.example.local",
					"port":465,
					"username":"mailer",
					"password":"fallback-secret",
					"auth":"cram_md5",
					"authSecret":"cram-secret",
					"fromEmail":"alerts@example.local",
					"encryption":"tls",
					"verifyMode":"none"
				}`),
			},
		},
		projectEmails: map[uuid.UUID][]string{projectID: {"admin@example.local"}},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	smtpMatcherA := fmt.Sprintf(`project_id="%s"`, projectID.String())
	smtpMatcherB := `connector_type="smtp"`
	route := findRouteByMatchers(cfg.Route.Routes, smtpMatcherA, smtpMatcherB)
	if route == nil {
		t.Fatalf("expected route with smtp/project matchers")
	}
	var smtpReceiver *alertmanagerReceiver
	for i := range cfg.Receivers {
		if cfg.Receivers[i].Name == route.Receiver {
			smtpReceiver = &cfg.Receivers[i]
			break
		}
	}
	if smtpReceiver == nil || len(smtpReceiver.EmailConfigs) != 1 {
		t.Fatalf("expected smtp receiver with one email config")
	}
	email := smtpReceiver.EmailConfigs[0]
	if email["smarthost"] != "smtp.example.local:465" {
		t.Fatalf("unexpected smarthost: %#v", email["smarthost"])
	}
	if email["require_tls"] != false {
		t.Fatalf("expected require_tls=false for 465/tls wrapper")
	}
	if strings.TrimSpace(fmt.Sprint(email["auth_secret"])) != "cram-secret" {
		t.Fatalf("expected auth_secret mapping")
	}
	tlsCfg, _ := email["tls_config"].(map[string]any)
	if tlsCfg["insecure_skip_verify"] != true {
		t.Fatalf("expected insecure_skip_verify=true, got %#v", tlsCfg)
	}
}

func TestRenderAlertmanagerYAML_SlackReceiver(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeSlack: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.local/services/a/b/c","defaultChannel":"#alerts"}`),
			},
		},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	matcherA := fmt.Sprintf(`project_id="%s"`, projectID.String())
	matcherB := `connector_type="slack"`
	route := findRouteByMatchers(cfg.Route.Routes, matcherA, matcherB)
	if route == nil {
		t.Fatalf("expected route with slack/project matchers")
	}
	var slackReceiver *alertmanagerReceiver
	for i := range cfg.Receivers {
		if cfg.Receivers[i].Name == route.Receiver {
			slackReceiver = &cfg.Receivers[i]
			break
		}
	}
	if slackReceiver == nil || len(slackReceiver.SlackConfigs) != 1 {
		t.Fatalf("expected slack receiver with one slack config")
	}
	slackCfg := slackReceiver.SlackConfigs[0]
	if slackCfg["api_url"] != "https://hooks.slack.local/services/a/b/c" {
		t.Fatalf("expected api_url alias mapping, got %#v", slackCfg["api_url"])
	}
	if slackCfg["channel"] != "#alerts" {
		t.Fatalf("expected channel alias mapping, got %#v", slackCfg["channel"])
	}
	if slackCfg["title"] != defaultSlackTitleTemplate {
		t.Fatalf("expected default slack title template, got %#v", slackCfg["title"])
	}
	if slackCfg["text"] != defaultSlackTextTemplate {
		t.Fatalf("expected default slack text template, got %#v", slackCfg["text"])
	}
	if slackCfg["title_link"] != defaultSlackTitleLinkTemplate {
		t.Fatalf("expected default slack title_link template, got %#v", slackCfg["title_link"])
	}
}

func TestRenderAlertmanagerYAML_ConnectorRouteRepeatIntervalOverride(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeSlack: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"webhookUrl":"https://hooks.slack.local/services/a/b/c",
					"repeatInterval":"15m"
				}`),
			},
		},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	matcherA := fmt.Sprintf(`project_id="%s"`, projectID.String())
	matcherB := `connector_type="slack"`
	route := findRouteByMatchers(cfg.Route.Routes, matcherA, matcherB)
	if route == nil {
		t.Fatalf("expected route with slack/project matchers")
	}
	if route.RepeatInterval != "15m" {
		t.Fatalf("expected route repeat_interval=15m, got %#v", route.RepeatInterval)
	}
}

func TestRenderAlertmanagerYAML_JiraIsNotRenderedAsAlertmanagerReceiver(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeJira: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeJira): {
				ConnectorType: store.ConnectorTypeJira,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"https://jira.example.local",
					"authMode":"api_token",
					"email":"admin@example.local",
					"apiToken":"secret",
					"requestTimeoutSeconds":10
				}`),
			},
		},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if len(cfg.Receivers) != 1 || cfg.Receivers[0].Name != "blackhole" {
		t.Fatalf("expected jira to be skipped from receivers, got %#v", cfg.Receivers)
	}
	if route := findRouteByMatchers(cfg.Route.Routes, fmt.Sprintf(`project_id="%s"`, projectID.String()), `connector_type="jira"`); route != nil {
		t.Fatalf("expected no jira route in alertmanager config, got %#v", route)
	}
}

func TestRenderAlertmanagerYAML_ExternalAlertmanagerIsNotRenderedAsReceiver(t *testing.T) {
	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeAlertmanagerExternal: {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeAlertmanagerExternal): {
				ConnectorType: store.ConnectorTypeAlertmanagerExternal,
				IsEnabled:     true,
				ConfigJSON: json.RawMessage(`{
					"baseUrl":"https://am.example.local",
					"authMode":"none",
					"timeoutSeconds":10
				}`),
			},
		},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}
	if len(cfg.Receivers) != 1 || cfg.Receivers[0].Name != "blackhole" {
		t.Fatalf("expected external alertmanager connector to be skipped from rendered receivers, got %#v", cfg.Receivers)
	}
	if route := findRouteByMatchers(cfg.Route.Routes, fmt.Sprintf(`project_id="%s"`, projectID.String()), `connector_type="alertmanager_external"`); route != nil {
		t.Fatalf("expected no external alertmanager route in rendered config, got %#v", route)
	}
}

func TestRenderAlertmanagerYAML_SkipsInvalidConnectorConfigButKeepsValidOnes(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "false")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "false")

	projectID := uuid.New()
	st := renderStoreStub{
		enabledProjects: map[store.ConnectorType][]uuid.UUID{
			store.ConnectorTypeSlack: {projectID},
			store.ConnectorTypeSNS:   {projectID},
		},
		projectConnectors: map[string]*store.ConnectorConfig{
			connectorKey(projectID, store.ConnectorTypeSlack): {
				ConnectorType: store.ConnectorTypeSlack,
				IsEnabled:     true,
				ConfigJSON:    json.RawMessage(`{"webhookUrl":"https://hooks.slack.local/services/a/b/c","defaultChannel":"#alerts"}`),
			},
			connectorKey(projectID, store.ConnectorTypeSNS): {
				ConnectorType: store.ConnectorTypeSNS,
				IsEnabled:     true,
				// Intentionally invalid under URL policy to emulate broken single connector config.
				ConfigJSON: json.RawMessage(`{
					"topicArn":"arn:aws:sns:us-east-1:000000000000:ctwall-test-topic",
					"apiUrl":"http://localhost:4566"
				}`),
			},
		},
	}

	data, err := renderAlertmanagerYAML(st, DefaultAlertmanagerIntegrationConfig())
	if err != nil {
		t.Fatalf("render config: %v", err)
	}

	var cfg alertmanagerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode yaml: %v", err)
	}

	slackRoute := findRouteByMatchers(
		cfg.Route.Routes,
		fmt.Sprintf(`project_id="%s"`, projectID.String()),
		`connector_type="slack"`,
	)
	if slackRoute == nil {
		t.Fatalf("expected valid slack route to be rendered")
	}

	snsRoute := findRouteByMatchers(
		cfg.Route.Routes,
		fmt.Sprintf(`project_id="%s"`, projectID.String()),
		`connector_type="sns"`,
	)
	if snsRoute != nil {
		t.Fatalf("expected invalid sns connector to be skipped, got route %#v", snsRoute)
	}
}

func TestIsRetryableAlertmanagerError_ContextDeadlineExceeded(t *testing.T) {
	if !isRetryableAlertmanagerError(context.DeadlineExceeded) {
		t.Fatalf("expected context deadline exceeded to be retryable")
	}
	if !isRetryableAlertmanagerError(errors.New("context deadline exceeded")) {
		t.Fatalf("expected deadline exceeded message to be retryable")
	}
}
