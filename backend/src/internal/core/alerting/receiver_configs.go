package alerting

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"backend/internal/store"
)

var connectorConfigAliases = map[store.ConnectorType]map[string]string{
	store.ConnectorTypeSlack: {
		"webhook_url":     "api_url",
		"webhookurl":      "api_url",
		"default_channel": "channel",
	},
	store.ConnectorTypeDiscord: {
		"webhookurl": "webhook_url",
	},
	store.ConnectorTypeMSTeamsV2: {
		"webhookurl": "webhook_url",
	},
	store.ConnectorTypeJira: {
		"base_url":    "api_url",
		"baseurl":     "api_url",
		"project_key": "project",
		"issue_type":  "issue_type",
	},
	store.ConnectorTypeSNS: {
		"base_url": "api_url",
		"baseurl":  "api_url",
	},
	store.ConnectorTypePagerDuty: {
		"routing_key": "routing_key",
	},
	store.ConnectorTypePushover: {
		"user_key": "user_key",
	},
	store.ConnectorTypeRocketChat: {
		"webhookurl": "webhook_url",
	},
	store.ConnectorTypeTelegram: {
		"bot_token": "bot_token",
		"chat_id":   "chat_id",
	},
	store.ConnectorTypeVictorOps: {
		"api_key":     "api_key",
		"routing_key": "routing_key",
	},
	store.ConnectorTypeWebex: {
		"base_url": "api_url",
		"room_id":  "room_id",
	},
	store.ConnectorTypeWebhook: {
		"webhook_url": "url",
		"webhookurl":  "url",
	},
	store.ConnectorTypeWeChat: {
		"api_secret": "api_secret",
		"corp_id":    "corp_id",
		"to_user":    "to_user",
		"to_party":   "to_party",
		"to_tag":     "to_tag",
		"agent_id":   "agent_id",
	},
}

var connectorRequiredFields = map[store.ConnectorType][]string{
	store.ConnectorTypeSlack:      {"api_url"},
	store.ConnectorTypeDiscord:    {"webhook_url"},
	store.ConnectorTypeMSTeamsV2:  {"webhook_url"},
	store.ConnectorTypeJira:       {"api_url"},
	store.ConnectorTypeOpsgenie:   {"api_key"},
	store.ConnectorTypePagerDuty:  {"routing_key"},
	store.ConnectorTypePushover:   {"user_key", "token"},
	store.ConnectorTypeRocketChat: {"webhook_url"},
	store.ConnectorTypeSNS:        {"topic_arn"},
	store.ConnectorTypeTelegram:   {"bot_token", "chat_id"},
	store.ConnectorTypeVictorOps:  {"api_key", "routing_key"},
	store.ConnectorTypeWebex:      {"api_url", "room_id"},
	store.ConnectorTypeWebhook:    {"url"},
	store.ConnectorTypeWeChat:     {"api_secret", "corp_id"},
}

var simpleTemplateTokenPattern = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

const (
	defaultSlackTitleTemplate     = `{{- $title := or (index .CommonAnnotations "title") "" -}}{{- if $title -}}{{ $title }}{{- else if gt (len .Alerts) 0 -}}{{ or (index (index .Alerts 0).Annotations "title") (or (index .CommonLabels "alertname") "CTWall alert") }}{{- else -}}{{ or (index .CommonLabels "alertname") "CTWall alert" }}{{- end -}}`
	defaultSlackTextTemplate      = `{{- $description := or (index .CommonAnnotations "description") "" -}}{{- if $description -}}{{ $description }}{{- else if gt (len .Alerts) 0 -}}{{ or (index (index .Alerts 0).Annotations "description") "" }}{{- end -}}`
	defaultSlackTitleLinkTemplate = `{{- $alertURL := or (index .CommonAnnotations "alert_url") "" -}}{{- if $alertURL -}}{{ $alertURL }}{{- else if gt (len .Alerts) 0 -}}{{ or (index (index .Alerts 0).Annotations "alert_url") "" }}{{- end -}}`
)

// ValidateAlertmanagerConnectorConfig validates per-project connector payloads.
// SMTP uses strict first-class parser; other receivers accept normalized object payloads and validate
// required fields + URL safety constraints (SSRF guard rails).
func ValidateAlertmanagerConnectorConfig(connectorType store.ConnectorType, raw json.RawMessage) error {
	if !store.ValidConnectorType(connectorType) {
		return fmt.Errorf("unsupported connector type")
	}
	if connectorType == store.ConnectorTypeAlertmanagerExternal {
		_, err := ParseExternalAlertmanagerConnectorConfig(raw)
		return err
	}
	if connectorType == store.ConnectorTypeSMTP {
		if _, err := ParseSMTPConfig(raw); err != nil {
			return err
		}
		_, err := parseConnectorRouteRepeatInterval(raw)
		return err
	}
	cfg, err := normalizeReceiverConfigObject(connectorType, raw)
	if err != nil {
		return err
	}
	required := connectorRequiredFields[connectorType]
	for _, key := range required {
		if strings.TrimSpace(asString(cfg[key])) == "" {
			return fmt.Errorf("%s requires '%s'", strings.ToLower(string(connectorType)), key)
		}
	}
	if err := validateReceiverURLs(cfg); err != nil {
		return err
	}
	if _, err := parseConnectorRouteRepeatIntervalFromNormalized(cfg); err != nil {
		return err
	}
	return nil
}

// BuildAlertmanagerReceiverConfig maps CTWall connector payload to Alertmanager receiver config object.
func BuildAlertmanagerReceiverConfig(connectorType store.ConnectorType, raw json.RawMessage, projectAdminEmails []string) (map[string]any, error) {
	if connectorType == store.ConnectorTypeAlertmanagerExternal {
		return nil, fmt.Errorf("external alertmanager connector is not rendered as internal alertmanager receiver")
	}
	if connectorType == store.ConnectorTypeSMTP {
		cfg, err := ParseSMTPConfig(raw)
		if err != nil {
			return nil, err
		}
		key, emails := canonicalEmailSet(projectAdminEmails)
		if strings.TrimSpace(key) == "" || len(emails) == 0 {
			return nil, fmt.Errorf("smtp receiver requires at least one project admin email")
		}
		out := map[string]any{
			"to":            strings.Join(emails, ","),
			"send_resolved": cfg.SendResolved,
			"smarthost":     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
			"from":          smtpFromAddress(cfg),
			"require_tls":   cfg.AlertmanagerRequireTLS(),
		}
		if messageTemplate := normalizeConnectorMessageTemplate(cfg.MessageTemplate); messageTemplate != "" {
			out["text"] = messageTemplate
		}
		if cfg.Domain != "" {
			out["hello"] = cfg.Domain
		}
		if cfg.Auth != "none" {
			out["auth_username"] = cfg.Username
			switch cfg.Auth {
			case "login", "plain":
				out["auth_password"] = cfg.Password
				if cfg.Auth == "plain" && strings.TrimSpace(cfg.AuthIdentity) != "" {
					out["auth_identity"] = cfg.AuthIdentity
				}
			case "cram_md5":
				secret := strings.TrimSpace(cfg.AuthSecret)
				if secret == "" {
					secret = cfg.Password
				}
				out["auth_secret"] = secret
			default:
				out["auth_password"] = cfg.Password
			}
		}
		if tlsCfg := smtpToAlertmanagerTLSConfig(cfg); tlsCfg != nil {
			tlsMap := map[string]any{}
			if strings.TrimSpace(tlsCfg.CAFile) != "" {
				tlsMap["ca_file"] = tlsCfg.CAFile
			}
			if strings.TrimSpace(tlsCfg.ServerName) != "" {
				tlsMap["server_name"] = tlsCfg.ServerName
			}
			if tlsCfg.InsecureSkipVerify {
				tlsMap["insecure_skip_verify"] = true
			}
			if len(tlsMap) > 0 {
				out["tls_config"] = tlsMap
			}
		}
		if replyTo := sanitizeSMTPHeaderValue(cfg.ReplyTo); replyTo != "" {
			out["headers"] = map[string]any{
				"Reply-To": replyTo,
			}
		}
		return out, nil
	}

	if err := ValidateAlertmanagerConnectorConfig(connectorType, raw); err != nil {
		return nil, err
	}
	cfg, err := normalizeReceiverConfigObject(connectorType, raw)
	if err != nil {
		return nil, err
	}
	stripConnectorRouteConfig(cfg)
	messageTemplate := normalizeConnectorMessageTemplate(asString(cfg["message_template"]))
	delete(cfg, "message_template")
	if messageTemplate != "" {
		switch connectorType {
		case store.ConnectorTypeSlack:
			cfg["text"] = messageTemplate
		case store.ConnectorTypeDiscord:
			cfg["message"] = messageTemplate
		}
	}
	if connectorType == store.ConnectorTypeSlack {
		// Alertmanager Slack receiver (v0.28.x) does not support bot_token.
		// Keep bot-token support only in direct connector test/send path, not in rendered AM config.
		delete(cfg, "bot_token")
		applySlackDefaults(cfg)
	}
	if connectorType == store.ConnectorTypeJira {
		// Jira connector in CTWall is ticket-oriented (issue create/update/close),
		// not notification-oriented; do not expose or render send_resolved toggle.
		delete(cfg, "send_resolved")
	} else if _, exists := cfg["send_resolved"]; !exists {
		cfg["send_resolved"] = true
	}
	return cfg, nil
}

func applySlackDefaults(cfg map[string]any) {
	if cfg == nil {
		return
	}
	if strings.TrimSpace(asString(cfg["title"])) == "" {
		cfg["title"] = defaultSlackTitleTemplate
	}
	if strings.TrimSpace(asString(cfg["text"])) == "" {
		cfg["text"] = defaultSlackTextTemplate
	}
	if strings.TrimSpace(asString(cfg["title_link"])) == "" {
		cfg["title_link"] = defaultSlackTitleLinkTemplate
	}
}

func parseConnectorRouteRepeatInterval(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", nil
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return "", fmt.Errorf("connector config must be a valid JSON object")
	}
	if cfg == nil {
		return "", nil
	}
	return parseConnectorRouteRepeatIntervalFromNormalized(normalizeMapKeys(cfg))
}

func parseConnectorRouteRepeatIntervalFromNormalized(cfg map[string]any) (string, error) {
	if cfg == nil {
		return "", nil
	}
	raw, exists := cfg["repeat_interval"]
	if !exists {
		return "", nil
	}
	if raw == nil {
		return "", nil
	}
	stringValue, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("repeat_interval must be a string duration (for example: 15m, 1h)")
	}
	value := strings.TrimSpace(stringValue)
	if value == "" {
		return "", nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return "", fmt.Errorf("repeat_interval must be a valid duration (for example: 15m, 1h)")
	}
	if duration <= 0 {
		return "", fmt.Errorf("repeat_interval must be greater than zero")
	}
	return value, nil
}

func stripConnectorRouteConfig(cfg map[string]any) {
	if cfg == nil {
		return
	}
	delete(cfg, "repeat_interval")
}

func normalizeReceiverConfigObject(connectorType store.ConnectorType, raw json.RawMessage) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		trimmed = "{}"
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
		return nil, fmt.Errorf("connector config must be a valid JSON object")
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	normalized := normalizeMapKeys(cfg)
	aliases := connectorConfigAliases[connectorType]
	for from, to := range aliases {
		fromKey := normalizeKey(from)
		toKey := normalizeKey(to)
		value, ok := normalized[fromKey]
		if !ok {
			continue
		}
		if _, exists := normalized[toKey]; !exists {
			normalized[toKey] = value
		}
		if fromKey != toKey {
			delete(normalized, fromKey)
		}
	}
	if connectorType == store.ConnectorTypeSNS {
		normalizeSNSConfig(normalized)
	}
	return normalized, nil
}

// normalizeSNSConfig maps flat SigV4 helper fields from UI payload
// to the nested Alertmanager SNS shape:
//
//	{ "sigv4": { "region": "...", "access_key": "...", "secret_key": "..." } }
func normalizeSNSConfig(cfg map[string]any) {
	if cfg == nil {
		return
	}

	sigv4 := map[string]any{}
	if existing, ok := cfg["sigv4"].(map[string]any); ok && existing != nil {
		for key, value := range existing {
			sigv4[key] = value
		}
	}

	moveToSigv4 := func(targetKey string, sourceKeys ...string) {
		for _, source := range sourceKeys {
			key := normalizeKey(source)
			value, ok := cfg[key]
			if !ok {
				continue
			}
			delete(cfg, key)
			if str, isString := value.(string); isString && strings.TrimSpace(str) == "" {
				continue
			}
			sigv4[targetKey] = value
			return
		}
	}

	moveToSigv4("region", "region", "sigv4_region")
	moveToSigv4("access_key", "access_key", "sigv4_access_key")
	moveToSigv4("secret_key", "secret_key", "sigv4_secret_key")
	moveToSigv4("profile", "profile", "sigv4_profile")
	moveToSigv4("role_arn", "role_arn", "sigv4_role_arn")

	if len(sigv4) > 0 {
		cfg["sigv4"] = sigv4
	}
}

func normalizeConnectorMessageTemplate(template string) string {
	trimmed := strings.TrimSpace(template)
	if trimmed == "" {
		return ""
	}
	return simpleTemplateTokenPattern.ReplaceAllStringFunc(trimmed, func(match string) string {
		parts := simpleTemplateTokenPattern.FindStringSubmatch(match)
		if len(parts) != 2 {
			return match
		}
		key := normalizeConnectorTemplateToken(parts[1])
		if key == "" {
			return match
		}
		return fmt.Sprintf(`{{ or (index .CommonLabels %q) "" }}`, key)
	})
}

func normalizeConnectorTemplateToken(token string) string {
	key := normalizeKey(token)
	switch key {
	case "group_key":
		return "dedup_key"
	default:
		return key
	}
}

func normalizeMapKeys(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		normalizedKey := normalizeKey(key)
		switch typed := value.(type) {
		case map[string]any:
			out[normalizedKey] = normalizeMapKeys(typed)
		case []any:
			out[normalizedKey] = normalizeArrayValues(typed)
		default:
			out[normalizedKey] = value
		}
	}
	return out
}

func normalizeArrayValues(values []any) []any {
	out := make([]any, len(values))
	for i := range values {
		switch typed := values[i].(type) {
		case map[string]any:
			out[i] = normalizeMapKeys(typed)
		case []any:
			out[i] = normalizeArrayValues(typed)
		default:
			out[i] = typed
		}
	}
	return out
}

func normalizeKey(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(input) + 8)
	var prevLowerOrDigit bool
	for _, r := range input {
		switch {
		case r == '-' || r == ' ':
			builder.WriteRune('_')
			prevLowerOrDigit = false
		case unicode.IsUpper(r):
			if prevLowerOrDigit {
				builder.WriteRune('_')
			}
			builder.WriteRune(unicode.ToLower(r))
			prevLowerOrDigit = false
		default:
			builder.WriteRune(unicode.ToLower(r))
			prevLowerOrDigit = unicode.IsLower(r) || unicode.IsDigit(r)
		}
	}
	return strings.Trim(builder.String(), "_")
}

func validateReceiverURLs(cfg map[string]any) error {
	requireAllowlist := envBool("ALERTING_REQUIRE_DOMAIN_ALLOWLIST", false)
	allowlist := parseDomainAllowlistEnv("ALERTING_TARGET_DOMAIN_ALLOWLIST")
	if requireAllowlist && len(allowlist) == 0 {
		return fmt.Errorf("ALERTING_TARGET_DOMAIN_ALLOWLIST is required")
	}
	return walkURLFields(cfg, allowlist)
}

func walkURLFields(node map[string]any, allowlist []string) error {
	for key, value := range node {
		switch typed := value.(type) {
		case string:
			if !isURLKey(key) {
				continue
			}
			if strings.TrimSpace(typed) == "" {
				continue
			}
			if err := validateOutboundURL(typed, allowlist); err != nil {
				return err
			}
		case map[string]any:
			if err := walkURLFields(typed, allowlist); err != nil {
				return err
			}
		case []any:
			for _, item := range typed {
				if nested, ok := item.(map[string]any); ok {
					if err := walkURLFields(nested, allowlist); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func isURLKey(key string) bool {
	normalized := normalizeKey(key)
	return normalized == "url" || strings.HasSuffix(normalized, "_url")
}

func validateOutboundURL(raw string, allowlist []string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return fmt.Errorf("invalid URL")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return fmt.Errorf("URL host is required")
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "https":
		// Allowed by default.
	case "http":
		if !envBool("ALERTING_ALLOW_HTTP_TARGETS", false) {
			return fmt.Errorf("http targets are disabled (set ALERTING_ALLOW_HTTP_TARGETS=true for local/dev)")
		}
	default:
		return fmt.Errorf("only https (or explicit dev http) is supported")
	}

	if strings.EqualFold(host, "localhost") {
		if !envBool("ALERTING_ALLOW_LOCALHOST_TARGETS", false) {
			return fmt.Errorf("localhost targets are disabled")
		}
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To16() != nil && ip.String() == "::1" {
			return fmt.Errorf("ipv6 loopback is not supported")
		}
		if ip.IsLoopback() {
			if ip4 := ip.To4(); ip4 != nil && ip4.String() == "127.0.0.1" && envBool("ALERTING_ALLOW_LOCALHOST_TARGETS", false) {
				return nil
			}
			return fmt.Errorf("loopback targets are blocked")
		}
		if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("private/link-local targets are blocked")
		}
		return nil
	}

	if len(allowlist) > 0 && !matchesAllowedDomain(host, allowlist) {
		return fmt.Errorf("target domain is not in allowlist")
	}
	return nil
}

func parseDomainAllowlistEnv(name string) []string {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(strings.ToLower(part))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func matchesAllowedDomain(host string, allowlist []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, allowed := range allowlist {
		allowed = strings.ToLower(strings.TrimSpace(allowed))
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func envBool(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
