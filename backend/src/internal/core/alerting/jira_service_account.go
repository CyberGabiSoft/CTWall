package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var jiraResolveCloudIDFn = jiraResolveCloudID

func jiraEffectiveBaseURL(ctx context.Context, cfg *JiraConnectorProfile, client *http.Client) string {
	if cfg == nil {
		return ""
	}
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		return ""
	}
	if !jiraNeedsServiceAccountCloudBase(cfg) {
		return strings.TrimRight(base, "/")
	}
	cloudID, err := jiraResolveCloudIDFn(ctx, base, client)
	if err != nil || strings.TrimSpace(cloudID) == "" {
		return strings.TrimRight(base, "/")
	}
	return "https://api.atlassian.com/ex/jira/" + strings.TrimSpace(cloudID)
}

func jiraCandidateBaseURLs(ctx context.Context, cfg *JiraConnectorProfile, client *http.Client) []string {
	if cfg == nil {
		return nil
	}
	original := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	effective := strings.TrimRight(strings.TrimSpace(jiraEffectiveBaseURL(ctx, cfg, client)), "/")

	seen := make(map[string]struct{}, 2)
	add := func(value string, out *[]string) {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			return
		}
		if _, ok := seen[normalized]; ok {
			return
		}
		seen[normalized] = struct{}{}
		*out = append(*out, normalized)
	}

	out := make([]string, 0, 2)
	// For Atlassian Cloud service accounts, some endpoints (notably issue transitions)
	// can return 404 on site base URL while working via api.atlassian.com/ex/jira/<cloudId>.
	// Prefer effective cloud base first to avoid false "issue not found" failures.
	if jiraNeedsServiceAccountCloudBase(cfg) {
		add(effective, &out)
		add(original, &out)
		return out
	}
	add(original, &out)
	add(effective, &out)
	return out
}

func jiraNeedsServiceAccountCloudBase(cfg *JiraConnectorProfile) bool {
	if cfg == nil || cfg.AuthMode != JiraAuthModeAPIToken {
		return false
	}
	email := strings.ToLower(strings.TrimSpace(cfg.Email))
	if !strings.HasSuffix(email, "@serviceaccount.atlassian.com") {
		return false
	}
	base := strings.ToLower(strings.TrimSpace(cfg.BaseURL))
	if strings.Contains(base, "api.atlassian.com/ex/jira/") {
		return false
	}
	return strings.Contains(base, ".atlassian.net")
}

func jiraResolveCloudID(ctx context.Context, baseURL string, client *http.Client) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	if host == "" || !strings.HasSuffix(host, ".atlassian.net") {
		return "", fmt.Errorf("unsupported jira host")
	}
	tenantInfoURL := parsed.Scheme + "://" + parsed.Host + "/_edge/tenant_info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tenantInfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("tenant info status %d", resp.StatusCode)
	}
	var payload struct {
		CloudID string `json:"cloudId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	return strings.TrimSpace(payload.CloudID), nil
}
