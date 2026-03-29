package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type ExternalAlertmanagerAuthMode string

const (
	ExternalAlertmanagerAuthNone   ExternalAlertmanagerAuthMode = "none"
	ExternalAlertmanagerAuthBasic  ExternalAlertmanagerAuthMode = "basic"
	ExternalAlertmanagerAuthBearer ExternalAlertmanagerAuthMode = "bearer"
)

type ExternalAlertmanagerConnectorConfig struct {
	BaseURL         string
	AuthMode        ExternalAlertmanagerAuthMode
	Username        string
	Password        string
	Token           string
	TimeoutSeconds  int
	SendResolved    bool
	AllowSelfSigned bool
}

func ParseExternalAlertmanagerConnectorConfig(raw json.RawMessage) (*ExternalAlertmanagerConnectorConfig, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return nil, errors.New("external alertmanager config is empty")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, errors.New("external alertmanager config must be a valid JSON object")
	}
	if parsed == nil {
		parsed = map[string]any{}
	}
	cfg := normalizeMapKeys(parsed)

	readString := func(keys ...string) string {
		for _, key := range keys {
			value, ok := cfg[normalizeKey(key)]
			if !ok {
				continue
			}
			if typed, ok := value.(string); ok {
				return strings.TrimSpace(typed)
			}
		}
		return ""
	}

	readInt := func(defaultValue int, keys ...string) int {
		for _, key := range keys {
			value, ok := cfg[normalizeKey(key)]
			if !ok || value == nil {
				continue
			}
			switch typed := value.(type) {
			case float64:
				return int(typed)
			case float32:
				return int(typed)
			case int:
				return typed
			case int64:
				return int(typed)
			case int32:
				return int(typed)
			case json.Number:
				if parsedInt, err := typed.Int64(); err == nil {
					return int(parsedInt)
				}
			case string:
				if parsedInt, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
					return parsedInt
				}
			}
		}
		return defaultValue
	}

	baseURL := readString("base_url", "baseUrl", "url")
	if baseURL == "" {
		return nil, errors.New("external alertmanager baseUrl is required")
	}
	requireAllowlist := envBool("ALERTING_REQUIRE_DOMAIN_ALLOWLIST", false)
	allowlist := parseDomainAllowlistEnv("ALERTING_TARGET_DOMAIN_ALLOWLIST")
	if requireAllowlist && len(allowlist) == 0 {
		return nil, errors.New("ALERTING_TARGET_DOMAIN_ALLOWLIST is required")
	}
	if err := validateOutboundURL(baseURL, allowlist); err != nil {
		return nil, fmt.Errorf("external alertmanager baseUrl is invalid: %w", err)
	}

	authMode := strings.ToLower(readString("auth_mode", "authMode"))
	if authMode == "" {
		authMode = string(ExternalAlertmanagerAuthNone)
	}

	timeoutSeconds := readInt(10, "timeout_seconds", "timeoutSeconds")
	if timeoutSeconds < 1 || timeoutSeconds > 60 {
		return nil, errors.New("external alertmanager timeoutSeconds must be between 1 and 60")
	}

	out := &ExternalAlertmanagerConnectorConfig{
		BaseURL:         strings.TrimRight(baseURL, "/"),
		AuthMode:        ExternalAlertmanagerAuthMode(authMode),
		Username:        readString("username"),
		Password:        readString("password"),
		Token:           readString("token", "bearer_token", "bearerToken", "api_token", "apiToken"),
		TimeoutSeconds:  timeoutSeconds,
		SendResolved:    readBoolOrDefault(cfg, true, "send_resolved", "sendResolved"),
		AllowSelfSigned: readBoolOrDefault(cfg, false, "allow_self_signed", "allowSelfSigned"),
	}

	switch out.AuthMode {
	case ExternalAlertmanagerAuthNone:
		// Nothing required.
	case ExternalAlertmanagerAuthBasic:
		if out.Username == "" {
			return nil, errors.New("external alertmanager username is required for authMode=basic")
		}
		if out.Password == "" {
			return nil, errors.New("external alertmanager password is required for authMode=basic")
		}
	case ExternalAlertmanagerAuthBearer:
		if out.Token == "" {
			return nil, errors.New("external alertmanager token is required for authMode=bearer")
		}
	default:
		return nil, errors.New("external alertmanager authMode must be one of: none, basic, bearer")
	}

	return out, nil
}

func NewExternalAlertmanagerClient(cfg *ExternalAlertmanagerConnectorConfig) (*AlertmanagerClient, error) {
	if cfg == nil {
		return nil, errors.New("external alertmanager config is nil")
	}
	options := AlertmanagerClientOptions{
		BaseURL:         cfg.BaseURL,
		AuthMode:        string(cfg.AuthMode),
		Username:        cfg.Username,
		Password:        cfg.Password,
		BearerToken:     cfg.Token,
		AllowSelfSigned: cfg.AllowSelfSigned,
		Timeout:         time.Duration(cfg.TimeoutSeconds) * time.Second,
	}
	return NewAlertmanagerClientWithOptions(options)
}

func TestExternalAlertmanagerConnection(ctx context.Context, cfg *ExternalAlertmanagerConnectorConfig) error {
	client, err := NewExternalAlertmanagerClient(cfg)
	if err != nil {
		return err
	}
	readyErr := client.Ready(ctx)
	if readyErr == nil {
		return nil
	}
	statusErr := client.Status(ctx)
	if statusErr == nil {
		return nil
	}
	return fmt.Errorf("external alertmanager health check failed: /-/ready=%v; /api/v2/status=%v", readyErr, statusErr)
}

func SendExternalAlertmanagerTestAlert(ctx context.Context, cfg *ExternalAlertmanagerConnectorConfig) error {
	client, err := NewExternalAlertmanagerClient(cfg)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	alert := AlertmanagerAlert{
		Labels: map[string]string{
			"alertname":      "CTWALL_EXTERNAL_ALERTMANAGER_CONNECTOR_TEST",
			"severity":       "INFO",
			"category":       "system",
			"connector_type": "alertmanager_external",
		},
		Annotations: map[string]string{
			"title":       "CTWall external Alertmanager connector test",
			"description": "This test alert confirms CTWall can deliver payloads to external Alertmanager.",
		},
		StartsAt: now.Format(time.RFC3339),
		EndsAt:   now.Add(5 * time.Minute).Format(time.RFC3339),
	}
	return client.PostAlerts(ctx, []AlertmanagerAlert{alert})
}

func readBoolOrDefault(values map[string]any, fallback bool, keys ...string) bool {
	for _, key := range keys {
		value, ok := values[normalizeKey(key)]
		if !ok || value == nil {
			continue
		}
		switch typed := value.(type) {
		case bool:
			return typed
		case float64:
			return typed != 0
		case float32:
			return typed != 0
		case int:
			return typed != 0
		case int64:
			return typed != 0
		case int32:
			return typed != 0
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			switch normalized {
			case "1", "true", "yes", "on":
				return true
			case "0", "false", "no", "off":
				return false
			}
		}
	}
	return fallback
}
