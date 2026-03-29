package alerting

import (
	"context"
	"net/http"
	"testing"
)

func TestJiraNeedsServiceAccountCloudBase(t *testing.T) {
	cfg := &JiraConnectorProfile{
		BaseURL:  "https://example.atlassian.net",
		AuthMode: JiraAuthModeAPIToken,
		Email:    "svc@serviceaccount.atlassian.com",
	}
	if !jiraNeedsServiceAccountCloudBase(cfg) {
		t.Fatalf("expected service account cloud base conversion to be needed")
	}

	cfg.BaseURL = "https://api.atlassian.com/ex/jira/abc"
	if jiraNeedsServiceAccountCloudBase(cfg) {
		t.Fatalf("did not expect conversion when api.atlassian.com base is already used")
	}
}

func TestJiraEffectiveBaseURL_UsesCloudBaseForServiceAccount(t *testing.T) {
	original := jiraResolveCloudIDFn
	t.Cleanup(func() { jiraResolveCloudIDFn = original })
	jiraResolveCloudIDFn = func(ctx context.Context, baseURL string, client *http.Client) (string, error) {
		return "cloud-123", nil
	}

	cfg := &JiraConnectorProfile{
		BaseURL:  "https://example.atlassian.net",
		AuthMode: JiraAuthModeAPIToken,
		Email:    "svc@serviceaccount.atlassian.com",
	}
	got := jiraEffectiveBaseURL(context.Background(), cfg, http.DefaultClient)
	want := "https://api.atlassian.com/ex/jira/cloud-123"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestJiraEffectiveBaseURL_FallsBackToConfiguredBase(t *testing.T) {
	cfg := &JiraConnectorProfile{
		BaseURL:  "https://jira.example.local/",
		AuthMode: JiraAuthModeBasic,
		Email:    "admin@example.local",
	}
	got := jiraEffectiveBaseURL(context.Background(), cfg, http.DefaultClient)
	want := "https://jira.example.local"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestJiraCandidateBaseURLs_ServiceAccountPrefersEffectiveBase(t *testing.T) {
	original := jiraResolveCloudIDFn
	t.Cleanup(func() { jiraResolveCloudIDFn = original })
	jiraResolveCloudIDFn = func(ctx context.Context, baseURL string, client *http.Client) (string, error) {
		return "cloud-123", nil
	}

	cfg := &JiraConnectorProfile{
		BaseURL:  "https://example.atlassian.net/",
		AuthMode: JiraAuthModeAPIToken,
		Email:    "svc@serviceaccount.atlassian.com",
	}
	got := jiraCandidateBaseURLs(context.Background(), cfg, http.DefaultClient)
	if len(got) != 2 {
		t.Fatalf("expected 2 base URLs, got %d: %#v", len(got), got)
	}
	if got[0] != "https://api.atlassian.com/ex/jira/cloud-123" {
		t.Fatalf("expected effective base first, got %q", got[0])
	}
	if got[1] != "https://example.atlassian.net" {
		t.Fatalf("expected original base second, got %q", got[1])
	}
}

func TestJiraCandidateBaseURLs_NonServiceAccountKeepsOriginalFirst(t *testing.T) {
	cfg := &JiraConnectorProfile{
		BaseURL:  "https://jira.example.local/",
		AuthMode: JiraAuthModeBasic,
		Username: "jira",
		Password: "secret",
	}
	got := jiraCandidateBaseURLs(context.Background(), cfg, http.DefaultClient)
	if len(got) != 1 {
		t.Fatalf("expected 1 base URL, got %d: %#v", len(got), got)
	}
	if got[0] != "https://jira.example.local" {
		t.Fatalf("expected original base URL, got %q", got[0])
	}
}
