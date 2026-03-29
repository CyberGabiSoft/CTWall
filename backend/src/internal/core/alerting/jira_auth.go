package alerting

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type jiraAuthMethod struct {
	apply func(*http.Request)
}

func jiraAuthMethods(cfg *JiraConnectorProfile) []jiraAuthMethod {
	if cfg == nil {
		return nil
	}

	switch cfg.AuthMode {
	case JiraAuthModeAPIToken:
		email := strings.TrimSpace(cfg.Email)
		token := strings.TrimSpace(cfg.APIToken)
		if token == "" {
			return nil
		}
		basic := jiraAuthMethod{
			apply: func(req *http.Request) {
				req.SetBasicAuth(email, token)
			},
		}
		if jiraIsAtlassianCloudBaseURL(cfg.BaseURL) {
			// Jira Cloud API tokens are used via Basic auth (email + token).
			// Bearer token fallback causes misleading 403 errors like
			// "Failed to parse Connect Session Auth Token".
			return []jiraAuthMethod{basic}
		}
		bearer := jiraAuthMethod{
			apply: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer "+token)
			},
		}
		return []jiraAuthMethod{basic, bearer}
	case JiraAuthModeBasic:
		username := strings.TrimSpace(cfg.Username)
		password := strings.TrimSpace(cfg.Password)
		if username == "" || password == "" {
			return nil
		}
		return []jiraAuthMethod{
			{
				apply: func(req *http.Request) {
					req.SetBasicAuth(username, password)
				},
			},
		}
	default:
		return nil
	}
}

func jiraIsAtlassianCloudBaseURL(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	return host == "api.atlassian.com" || strings.HasSuffix(host, ".atlassian.net")
}

func jiraAuthFailedLoginReason(headerValue string) bool {
	normalized := strings.TrimSpace(strings.ToUpper(headerValue))
	if normalized == "" {
		return false
	}
	return strings.Contains(normalized, "AUTHENTICATED_FAILED")
}

func jiraDoRequestWithAuthFallback(
	client *http.Client,
	buildReq func() (*http.Request, error),
	authMethods []jiraAuthMethod,
	bodyLimit int64,
) (statusCode int, body []byte, err error) {
	if client == nil {
		return 0, nil, errors.New("jira http client is nil")
	}
	if len(authMethods) == 0 {
		return 0, nil, errors.New("jira auth config is empty")
	}

	for idx := range authMethods {
		req, buildErr := buildReq()
		if buildErr != nil {
			return 0, nil, buildErr
		}
		authMethods[idx].apply(req)

		resp, requestErr := client.Do(req)
		if requestErr != nil {
			return 0, nil, requestErr
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
		authFailedByHeader := jiraAuthFailedLoginReason(resp.Header.Get("X-Seraph-LoginReason"))
		_ = resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 && authFailedByHeader {
			if idx < len(authMethods)-1 {
				continue
			}
			return http.StatusUnauthorized, respBody, fmt.Errorf("jira authentication failed (%d): anonymous response", http.StatusUnauthorized)
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if idx < len(authMethods)-1 {
				continue
			}
			// For scoped Jira tokens, auth can be valid but insufficient for endpoint scopes.
			// Let caller decide based on status/body instead of forcing auth error here.
			if jiraScopeMismatchBody(respBody) {
				return resp.StatusCode, respBody, nil
			}
			message := strings.TrimSpace(string(respBody))
			if message == "" {
				return resp.StatusCode, respBody, fmt.Errorf("jira authentication failed (%d)", resp.StatusCode)
			}
			if len(message) > 240 {
				message = message[:240]
			}
			return resp.StatusCode, respBody, fmt.Errorf("jira authentication failed (%d): %s", resp.StatusCode, message)
		}
		return resp.StatusCode, respBody, nil
	}

	return 0, nil, errors.New("jira request failed")
}
