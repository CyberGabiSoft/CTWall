package alerting

import (
	"encoding/json"
	"testing"

	"backend/internal/store"
)

func TestValidateAlertmanagerConnectorConfig_SMTP(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":587,
		"username":"mailer",
		"password":"secret",
		"auth":"login",
		"fromEmail":"alerts@example.local",
		"encryption":"starttls",
		"verifyMode":"peer"
	}`)
	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeSMTP, raw); err != nil {
		t.Fatalf("expected smtp config valid: %v", err)
	}
}

func TestValidateAlertmanagerConnectorConfig_URLPolicy(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "false")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "false")

	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeWebhook, json.RawMessage(`{"url":"http://localhost:8080/hook"}`)); err == nil {
		t.Fatalf("expected localhost/http target to be blocked without dev flags")
	}

	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeWebhook, json.RawMessage(`{"url":"http://127.0.0.1:8080/hook"}`)); err != nil {
		t.Fatalf("expected localhost target allowed with dev flags: %v", err)
	}
	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeWebhook, json.RawMessage(`{"url":"http://[::1]:8080/hook"}`)); err == nil {
		t.Fatalf("expected ipv6 loopback to be blocked")
	}
}

func TestValidateAlertmanagerConnectorConfig_RequiredFields(t *testing.T) {
	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypePagerDuty, json.RawMessage(`{}`)); err == nil {
		t.Fatalf("expected pagerduty config validation error")
	}
}

func TestValidateAlertmanagerConnectorConfig_RejectsInvalidRepeatInterval(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://hooks.slack.local/services/a/b/c",
		"repeatInterval":"every-15-minutes"
	}`)
	if err := ValidateAlertmanagerConnectorConfig(store.ConnectorTypeSlack, raw); err == nil {
		t.Fatalf("expected repeat_interval validation error")
	}
}

func TestBuildAlertmanagerReceiverConfig_SMTP(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":465,
		"username":"mailer",
		"password":"secret",
		"auth":"cram_md5",
		"fromEmail":"alerts@example.local",
		"encryption":"tls",
		"verifyMode":"none"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSMTP, raw, []string{"Admin@Example.Local"})
	if err != nil {
		t.Fatalf("build smtp receiver config: %v", err)
	}
	if cfg["to"] != "admin@example.local" {
		t.Fatalf("expected normalized recipient list, got %#v", cfg["to"])
	}
	if cfg["require_tls"] != false {
		t.Fatalf("expected require_tls=false for 465/tls wrapper")
	}
	if cfg["auth_secret"] != "secret" {
		t.Fatalf("expected auth_secret fallback, got %#v", cfg["auth_secret"])
	}
	if cfg["send_resolved"] != true {
		t.Fatalf("expected send_resolved=true by default, got %#v", cfg["send_resolved"])
	}
}

func TestBuildAlertmanagerReceiverConfig_SMTP_SendResolvedFalse(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":587,
		"username":"mailer",
		"password":"secret",
		"auth":"login",
		"fromEmail":"alerts@example.local",
		"encryption":"starttls",
		"verifyMode":"peer",
		"sendResolved":false
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSMTP, raw, []string{"admin@example.local"})
	if err != nil {
		t.Fatalf("build smtp receiver config: %v", err)
	}
	if cfg["send_resolved"] != false {
		t.Fatalf("expected send_resolved=false, got %#v", cfg["send_resolved"])
	}
}

func TestBuildAlertmanagerReceiverConfig_SlackAliases(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://hooks.slack.local/services/a/b/c",
		"defaultChannel":"#alerts",
		"repeatInterval":"15m"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSlack, raw, nil)
	if err != nil {
		t.Fatalf("build slack receiver config: %v", err)
	}
	if cfg["api_url"] != "https://hooks.slack.local/services/a/b/c" {
		t.Fatalf("expected api_url alias mapping, got %#v", cfg["api_url"])
	}
	if cfg["channel"] != "#alerts" {
		t.Fatalf("expected channel alias mapping, got %#v", cfg["channel"])
	}
	if cfg["title"] != defaultSlackTitleTemplate {
		t.Fatalf("expected default slack title template, got %#v", cfg["title"])
	}
	if cfg["text"] != defaultSlackTextTemplate {
		t.Fatalf("expected default slack text template, got %#v", cfg["text"])
	}
	if cfg["title_link"] != defaultSlackTitleLinkTemplate {
		t.Fatalf("expected default slack title_link template, got %#v", cfg["title_link"])
	}
	if _, exists := cfg["repeat_interval"]; exists {
		t.Fatalf("expected repeat_interval to be stripped from receiver config")
	}
	if cfg["send_resolved"] != true {
		t.Fatalf("expected default send_resolved=true")
	}
}

func TestBuildAlertmanagerReceiverConfig_SlackSendResolvedFalse(t *testing.T) {
	raw := json.RawMessage(`{"webhookUrl":"https://hooks.slack.local/services/a/b/c","sendResolved":false}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSlack, raw, nil)
	if err != nil {
		t.Fatalf("build slack receiver config: %v", err)
	}
	if cfg["send_resolved"] != false {
		t.Fatalf("expected send_resolved=false, got %#v", cfg["send_resolved"])
	}
}

func TestBuildAlertmanagerReceiverConfig_SlackDropsBotTokenField(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://hooks.slack.local/services/a/b/c",
		"botToken":"xoxb-should-not-be-rendered",
		"defaultChannel":"#alerts"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSlack, raw, nil)
	if err != nil {
		t.Fatalf("build slack receiver config: %v", err)
	}
	if _, exists := cfg["bot_token"]; exists {
		t.Fatalf("expected bot_token to be removed from rendered slack receiver config")
	}
}

func TestBuildAlertmanagerReceiverConfig_SlackMessageTemplate(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://hooks.slack.local/services/a/b/c",
		"messageTemplate":"Alert {{severity}} {{product}}"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSlack, raw, nil)
	if err != nil {
		t.Fatalf("build slack receiver config: %v", err)
	}
	if cfg["text"] != `Alert {{ or (index .CommonLabels "severity") "" }} {{ or (index .CommonLabels "product") "" }}` {
		t.Fatalf("expected slack text template mapping, got %#v", cfg["text"])
	}
	if _, exists := cfg["message_template"]; exists {
		t.Fatalf("expected message_template to be removed from rendered receiver config")
	}
}

func TestBuildAlertmanagerReceiverConfig_DiscordMessageTemplate(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://discord.example.local/webhook",
		"messageTemplate":"Alert {{severity}} {{product}}"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeDiscord, raw, nil)
	if err != nil {
		t.Fatalf("build discord receiver config: %v", err)
	}
	if cfg["message"] != `Alert {{ or (index .CommonLabels "severity") "" }} {{ or (index .CommonLabels "product") "" }}` {
		t.Fatalf("expected discord message template mapping, got %#v", cfg["message"])
	}
	if _, exists := cfg["message_template"]; exists {
		t.Fatalf("expected message_template to be removed from rendered receiver config")
	}
}

func TestBuildAlertmanagerReceiverConfig_SMTP_MessageTemplate(t *testing.T) {
	raw := json.RawMessage(`{
		"host":"smtp.example.local",
		"port":587,
		"username":"mailer",
		"password":"secret",
		"auth":"login",
		"fromEmail":"alerts@example.local",
		"encryption":"starttls",
		"verifyMode":"peer",
		"messageTemplate":"Alert {{severity}} {{product}}"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSMTP, raw, []string{"admin@example.local"})
	if err != nil {
		t.Fatalf("build smtp receiver config: %v", err)
	}
	if cfg["text"] != `Alert {{ or (index .CommonLabels "severity") "" }} {{ or (index .CommonLabels "product") "" }}` {
		t.Fatalf("expected smtp text template mapping, got %#v", cfg["text"])
	}
}

func TestBuildAlertmanagerReceiverConfig_MessageTemplatePreservesNativeExpressions(t *testing.T) {
	raw := json.RawMessage(`{
		"webhookUrl":"https://hooks.slack.local/services/a/b/c",
		"messageTemplate":"{{ .Status }} :: {{severity}} :: {{group_key}}"
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSlack, raw, nil)
	if err != nil {
		t.Fatalf("build slack receiver config: %v", err)
	}
	if cfg["text"] != `{{ .Status }} :: {{ or (index .CommonLabels "severity") "" }} :: {{ or (index .CommonLabels "dedup_key") "" }}` {
		t.Fatalf("expected mixed template conversion, got %#v", cfg["text"])
	}
}

func TestBuildAlertmanagerReceiverConfig_JiraOmitsSendResolvedByDefault(t *testing.T) {
	raw := json.RawMessage(`{"apiUrl":"https://jira.example.local","project":"SEC","issueType":"Bug"}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeJira, raw, nil)
	if err != nil {
		t.Fatalf("build jira receiver config: %v", err)
	}
	if _, exists := cfg["send_resolved"]; exists {
		t.Fatalf("expected send_resolved to be omitted for jira")
	}
}

func TestBuildAlertmanagerReceiverConfig_JiraDropsProvidedSendResolved(t *testing.T) {
	raw := json.RawMessage(`{"apiUrl":"https://jira.example.local","project":"SEC","issueType":"Bug","sendResolved":false}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeJira, raw, nil)
	if err != nil {
		t.Fatalf("build jira receiver config: %v", err)
	}
	if _, exists := cfg["send_resolved"]; exists {
		t.Fatalf("expected send_resolved to be omitted for jira even when provided")
	}
}

func TestBuildAlertmanagerReceiverConfig_SNSMapsSigV4Fields(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	raw := json.RawMessage(`{
		"topicArn":"arn:aws:sns:us-east-1:000000000000:ctwall-test-topic",
		"apiUrl":"http://ctwall-localstack:4566",
		"region":"us-east-1",
		"accessKey":"test",
		"secretKey":"test",
		"sendResolved":false
	}`)
	cfg, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeSNS, raw, nil)
	if err != nil {
		t.Fatalf("build sns receiver config: %v", err)
	}
	if cfg["topic_arn"] != "arn:aws:sns:us-east-1:000000000000:ctwall-test-topic" {
		t.Fatalf("expected topic_arn mapping, got %#v", cfg["topic_arn"])
	}
	if cfg["api_url"] != "http://ctwall-localstack:4566" {
		t.Fatalf("expected api_url mapping, got %#v", cfg["api_url"])
	}
	if cfg["send_resolved"] != false {
		t.Fatalf("expected send_resolved=false, got %#v", cfg["send_resolved"])
	}
	sigv4Raw, ok := cfg["sigv4"].(map[string]any)
	if !ok {
		t.Fatalf("expected sigv4 map, got %#v", cfg["sigv4"])
	}
	if sigv4Raw["region"] != "us-east-1" {
		t.Fatalf("expected sigv4.region, got %#v", sigv4Raw["region"])
	}
	if sigv4Raw["access_key"] != "test" {
		t.Fatalf("expected sigv4.access_key, got %#v", sigv4Raw["access_key"])
	}
	if sigv4Raw["secret_key"] != "test" {
		t.Fatalf("expected sigv4.secret_key, got %#v", sigv4Raw["secret_key"])
	}
}

func TestBuildAlertmanagerReceiverConfig_ExternalAlertmanagerNotRendered(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	raw := json.RawMessage(`{
		"baseUrl":"http://127.0.0.1:9093",
		"authMode":"none",
		"timeoutSeconds":10
	}`)
	if _, err := BuildAlertmanagerReceiverConfig(store.ConnectorTypeAlertmanagerExternal, raw, nil); err == nil {
		t.Fatalf("expected external alertmanager to be rejected in receiver renderer")
	}
}
