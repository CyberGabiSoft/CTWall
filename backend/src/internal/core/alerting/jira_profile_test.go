package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseJiraConnectorProfile_APITokenMode(t *testing.T) {
	raw := json.RawMessage(`{
		"baseUrl":"https://jira.example.local",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"requestTimeoutSeconds":15,
		"deploymentMode":"auto"
	}`)
	cfg, err := ParseJiraConnectorProfile(raw)
	if err != nil {
		t.Fatalf("expected valid jira config, got %v", err)
	}
	if cfg.BaseURL != "https://jira.example.local" {
		t.Fatalf("unexpected base url: %s", cfg.BaseURL)
	}
	if cfg.AuthMode != JiraAuthModeAPIToken {
		t.Fatalf("unexpected auth mode: %s", cfg.AuthMode)
	}
	if cfg.RequestTimeoutSeconds != 15 {
		t.Fatalf("unexpected timeout: %d", cfg.RequestTimeoutSeconds)
	}
}

func TestParseJiraConnectorProfile_BasicMode(t *testing.T) {
	raw := json.RawMessage(`{
		"base_url":"https://jira.example.local",
		"auth_mode":"basic",
		"username":"jira-user",
		"password":"secret"
	}`)
	cfg, err := ParseJiraConnectorProfile(raw)
	if err != nil {
		t.Fatalf("expected valid jira config, got %v", err)
	}
	if cfg.AuthMode != JiraAuthModeBasic {
		t.Fatalf("unexpected auth mode: %s", cfg.AuthMode)
	}
	if cfg.Username != "jira-user" {
		t.Fatalf("unexpected username: %s", cfg.Username)
	}
}

func TestParseJiraConnectorProfile_BasicMode_EmailWithoutUsernameRejected(t *testing.T) {
	raw := json.RawMessage(`{
		"base_url":"https://jira.example.local",
		"auth_mode":"basic",
		"email":"jira-user@example.local",
		"password":"secret"
	}`)
	_, err := ParseJiraConnectorProfile(raw)
	if err == nil {
		t.Fatalf("expected username validation error")
	}
}

func TestParseJiraConnectorProfile_APITokenMode_UsernameWithoutEmailRejected(t *testing.T) {
	raw := json.RawMessage(`{
		"base_url":"https://jira.example.local",
		"auth_mode":"api_token",
		"username":"admin@example.local",
		"api_token":"secret"
	}`)
	_, err := ParseJiraConnectorProfile(raw)
	if err == nil {
		t.Fatalf("expected email validation error")
	}
}

func TestParseJiraConnectorProfile_MissingRequiredFields(t *testing.T) {
	if _, err := ParseJiraConnectorProfile(json.RawMessage(`{}`)); err == nil {
		t.Fatalf("expected error for empty jira config")
	}
	if _, err := ParseJiraConnectorProfile(json.RawMessage(`{"baseUrl":"https://jira.example.local","authMode":"api_token"}`)); err == nil {
		t.Fatalf("expected credential validation error")
	}
}

func TestTestJiraConnection_AutoFallbackToV2(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	var gotV3 bool
	var gotV2 bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/search":
			gotV3 = true
			w.WriteHeader(http.StatusNotFound)
		case "/rest/api/2/project/search":
			gotV2 = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"values":[],"isLast":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"deploymentMode":"auto",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := TestJiraConnection(context.Background(), cfg); err != nil {
		t.Fatalf("test connection failed: %v", err)
	}
	if !gotV3 || !gotV2 {
		t.Fatalf("expected auto mode to try v3 then v2 (v3=%v v2=%v)", gotV3, gotV2)
	}
}

func TestTestJiraConnection_APITokenBearerFallback(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	var authHeaders []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, strings.TrimSpace(r.Header.Get("Authorization")))
		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"values":[],"isLast":true}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"deploymentMode":"cloud",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if err := TestJiraConnection(context.Background(), cfg); err != nil {
		t.Fatalf("test connection failed: %v", err)
	}
	if len(authHeaders) != 2 {
		t.Fatalf("expected 2 auth attempts (basic + bearer), got %d", len(authHeaders))
	}
	if !strings.HasPrefix(authHeaders[0], "Basic ") {
		t.Fatalf("expected first auth attempt to use Basic, got %q", authHeaders[0])
	}
	if !strings.HasPrefix(authHeaders[1], "Bearer ") {
		t.Fatalf("expected second auth attempt to use Bearer, got %q", authHeaders[1])
	}
}

func TestJiraAuthMethods_APITokenServiceAccountUsesBasicFirst(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"https://tenant.atlassian.net",
		"authMode":"api_token",
		"email":"bot@serviceaccount.atlassian.com",
		"apiToken":"secret",
		"deploymentMode":"cloud",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	methods := jiraAuthMethods(cfg)
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method for Jira Cloud API token, got %d", len(methods))
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.local", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	methods[0].apply(req)
	if got := strings.TrimSpace(req.Header.Get("Authorization")); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("expected first auth method to set Basic, got %q", got)
	}
}

func TestTestJiraConnection_AuthFailedAnonymous200FallsBack(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	var authHeaders []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, strings.TrimSpace(r.Header.Get("Authorization")))
		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Basic ") {
			w.Header().Set("X-Seraph-LoginReason", "AUTHENTICATED_FAILED")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"values":[],"isLast":true}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"values":[],"isLast":true}`))
	}))
	defer srv.Close()

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"deploymentMode":"cloud",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if err := TestJiraConnection(context.Background(), cfg); err != nil {
		t.Fatalf("test connection failed: %v", err)
	}
	if len(authHeaders) != 2 {
		t.Fatalf("expected 2 auth attempts (basic + bearer), got %d", len(authHeaders))
	}
	if !strings.HasPrefix(authHeaders[0], "Basic ") {
		t.Fatalf("expected first auth attempt to use Basic, got %q", authHeaders[0])
	}
	if !strings.HasPrefix(authHeaders[1], "Bearer ") {
		t.Fatalf("expected second auth attempt to use Bearer, got %q", authHeaders[1])
	}
}

func TestTestJiraConnection_AuthOnlyTreatsScopeMismatchAsSuccess(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Unauthorized; scope does not match"}`))
	}))
	defer srv.Close()

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"deploymentMode":"cloud",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if err := TestJiraConnection(context.Background(), cfg); err != nil {
		t.Fatalf("expected auth-only scope mismatch to pass, got error: %v", err)
	}
}

func TestTestJiraConnection_AuthFailureStillFails(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Unauthorized"}`))
	}))
	defer srv.Close()

	cfg, err := ParseJiraConnectorProfile(json.RawMessage(`{
		"baseUrl":"` + srv.URL + `",
		"authMode":"api_token",
		"email":"admin@example.local",
		"apiToken":"secret",
		"deploymentMode":"cloud",
		"requestTimeoutSeconds":10
	}`))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if err := TestJiraConnection(context.Background(), cfg); err == nil {
		t.Fatalf("expected unauthorized auth failure")
	}
}
