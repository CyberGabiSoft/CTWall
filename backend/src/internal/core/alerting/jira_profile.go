package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type JiraAuthMode string

const (
	JiraAuthModeAPIToken JiraAuthMode = "api_token"
	JiraAuthModeBasic    JiraAuthMode = "basic"
)

type JiraDeploymentMode string

const (
	JiraDeploymentAuto       JiraDeploymentMode = "auto"
	JiraDeploymentCloud      JiraDeploymentMode = "cloud"
	JiraDeploymentDataCenter JiraDeploymentMode = "datacenter"
)

type JiraConnectorProfile struct {
	BaseURL               string
	AuthMode              JiraAuthMode
	RequestTimeoutSeconds int
	DeploymentMode        JiraDeploymentMode
	Email                 string
	Username              string
	APIToken              string
	Password              string
}

func ParseJiraConnectorProfile(raw json.RawMessage) (*JiraConnectorProfile, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "{}" {
		return nil, errors.New("jira config is empty")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return nil, errors.New("jira config must be a valid JSON object")
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

	baseURL := readString("base_url", "baseUrl", "api_url", "apiUrl")
	if baseURL == "" {
		return nil, errors.New("jira baseUrl is required")
	}
	requireAllowlist := envBool("ALERTING_REQUIRE_DOMAIN_ALLOWLIST", false)
	allowlist := parseDomainAllowlistEnv("ALERTING_TARGET_DOMAIN_ALLOWLIST")
	if requireAllowlist && len(allowlist) == 0 {
		return nil, errors.New("ALERTING_TARGET_DOMAIN_ALLOWLIST is required")
	}
	if err := validateOutboundURL(baseURL, allowlist); err != nil {
		return nil, fmt.Errorf("jira baseUrl is invalid: %w", err)
	}

	authMode := strings.ToLower(readString("auth_mode", "authMode"))
	if authMode == "" {
		authMode = string(JiraAuthModeAPIToken)
	}
	deploymentMode := strings.ToLower(readString("deployment_mode", "deploymentMode"))
	if deploymentMode == "" {
		deploymentMode = string(JiraDeploymentAuto)
	}

	timeoutSeconds := readInt(10, "request_timeout_seconds", "requestTimeoutSeconds", "timeout_seconds", "timeoutSeconds")
	if timeoutSeconds < 1 || timeoutSeconds > 60 {
		return nil, errors.New("jira requestTimeoutSeconds must be between 1 and 60")
	}

	out := &JiraConnectorProfile{
		BaseURL:               strings.TrimRight(baseURL, "/"),
		AuthMode:              JiraAuthMode(authMode),
		RequestTimeoutSeconds: timeoutSeconds,
		DeploymentMode:        JiraDeploymentMode(deploymentMode),
		Email:                 readString("email"),
		Username:              readString("username"),
		APIToken:              readString("api_token", "apiToken"),
		Password:              readString("password"),
	}

	switch out.DeploymentMode {
	case JiraDeploymentAuto, JiraDeploymentCloud, JiraDeploymentDataCenter:
		// ok
	default:
		return nil, errors.New("jira deploymentMode must be one of: auto, cloud, datacenter")
	}

	switch out.AuthMode {
	case JiraAuthModeAPIToken:
		if out.Email == "" {
			return nil, errors.New("jira email is required for authMode=api_token")
		}
		if out.APIToken == "" {
			return nil, errors.New("jira apiToken is required for authMode=api_token")
		}
	case JiraAuthModeBasic:
		if strings.Contains(strings.ToLower(strings.TrimSpace(out.BaseURL)), ".atlassian.net") {
			return nil, errors.New("jira cloud does not support browser password basic auth for REST API; use authMode=api_token with Atlassian API token")
		}
		if out.Username == "" {
			return nil, errors.New("jira username is required for authMode=basic")
		}
		if out.Password == "" {
			return nil, errors.New("jira password is required for authMode=basic")
		}
	default:
		return nil, errors.New("jira authMode must be one of: api_token, basic")
	}

	return out, nil
}

func TestJiraConnection(ctx context.Context, cfg *JiraConnectorProfile) error {
	if cfg == nil {
		return errors.New("jira config is nil")
	}
	authMethods := jiraAuthMethods(cfg)
	if len(authMethods) == 0 {
		return errors.New("jira auth config is empty")
	}
	timeout := time.Duration(cfg.RequestTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	baseURLs := jiraCandidateBaseURLs(ctx, cfg, client)
	if len(baseURLs) == 0 {
		baseURLs = []string{strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")}
	}

	versions := jiraAPIVersions(cfg.DeploymentMode)
	var lastErr error
	for baseIdx := range baseURLs {
		baseURL := strings.TrimRight(strings.TrimSpace(baseURLs[baseIdx]), "/")
		for idx, version := range versions {
			testURL := fmt.Sprintf("%s/rest/api/%d/project/search?maxResults=1", baseURL, version)
			statusCode, body, err := jiraDoRequestWithAuthFallback(client, func() (*http.Request, error) {
				req, buildErr := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
				if buildErr != nil {
					return nil, buildErr
				}
				req.Header.Set("Accept", "application/json")
				return req, nil
			}, authMethods, 2048)
			if err != nil {
				if cfg.AuthMode == JiraAuthModeBasic &&
					strings.Contains(strings.ToLower(strings.TrimSpace(cfg.BaseURL)), ".atlassian.net") {
					return errors.New("jira cloud does not support browser password basic auth for REST API; use authMode=api_token with Atlassian API token")
				}
				var statusErr HTTPStatusError
				if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound &&
					cfg.DeploymentMode == JiraDeploymentAuto && idx < len(versions)-1 {
					lastErr = err
					continue
				}
				if statusCode, ok := ParseHTTPStatusCode(err); ok &&
					(statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
					baseIdx < len(baseURLs)-1 {
					lastErr = err
					break
				}
				return err
			}

			if statusCode >= 200 && statusCode < 300 {
				return nil
			}
			// Auth-only compatibility mode:
			// Jira Cloud can return 401 "scope does not match" for scoped tokens even when
			// credentials are valid. Treat this as successful authentication for connector test.
			if statusCode == http.StatusUnauthorized && jiraScopeMismatchBody(body) {
				return nil
			}
			if statusCode == http.StatusNotFound &&
				cfg.DeploymentMode == JiraDeploymentAuto &&
				idx < len(versions)-1 {
				lastErr = errors.New("jira v3 endpoint unavailable")
				continue
			}
			lastErr = HTTPStatusError{StatusCode: statusCode, Body: strings.TrimSpace(string(body))}
			if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
				baseIdx < len(baseURLs)-1 {
				break
			}
			return lastErr
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("jira connection test failed")
}

func jiraScopeMismatchBody(body []byte) bool {
	normalized := strings.ToLower(strings.TrimSpace(string(body)))
	if normalized == "" {
		return false
	}
	return strings.Contains(normalized, "scope does not match")
}
