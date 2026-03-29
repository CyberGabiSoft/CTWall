package alerting

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestJiraDoJSON_AuthErrorOnFirstCandidateFallsBackToNextBaseURL(t *testing.T) {
	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"https://acme.atlassian.net",
		"authMode":"api_token",
		"email":"svc@serviceaccount.atlassian.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"auto"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	originalResolve := jiraResolveCloudIDFn
	jiraResolveCloudIDFn = func(context.Context, string, *http.Client) (string, error) {
		return "cloud-123", nil
	}
	defer func() {
		jiraResolveCloudIDFn = originalResolve
	}()

	requestedHosts := make([]string, 0, 4)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestedHosts = append(requestedHosts, req.URL.Host)
			switch req.URL.Host {
			case "api.atlassian.com":
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"errorMessages":["not authenticated"],"errors":{}}`)),
				}, nil
			case "acme.atlassian.net":
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`[{"id":"1","name":"High"}]`)),
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusNotFound,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(`{"errorMessages":["not found"],"errors":{}}`)),
				}, nil
			}
		}),
	}

	respBody, _, err := jiraDoJSON(
		context.Background(),
		cfg,
		client,
		http.MethodGet,
		"/rest/api/%d/priority",
		nil,
		http.StatusOK,
	)
	if err != nil {
		t.Fatalf("expected fallback to second base URL, got error: %v", err)
	}
	if !strings.Contains(string(respBody), `"High"`) {
		t.Fatalf("expected priorities payload from fallback base URL, got: %s", string(respBody))
	}

	joined := strings.Join(requestedHosts, ",")
	if !strings.Contains(joined, "acme.atlassian.net") {
		t.Fatalf("expected fallback request to acme.atlassian.net, hosts: %s", joined)
	}
}

func TestJiraListProjects_SearchEmptyDoesNotFallbackToLegacyProjectEndpoint(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	calledProjectSearch := 0
	calledLegacyProject := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/search":
			calledProjectSearch++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"values":[],"isLast":true}`)
		case "/rest/api/3/project":
			calledLegacyProject++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"errorMessages":["auth failed"],"errors":{}}`)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	projects, err := JiraListProjects(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected empty projects without error, got: %v", err)
	}
	if len(projects) != 0 {
		t.Fatalf("expected zero projects, got %d", len(projects))
	}
	if calledProjectSearch == 0 {
		t.Fatalf("expected /project/search to be called")
	}
	if calledLegacyProject != 0 {
		t.Fatalf("did not expect fallback /project call when /project/search succeeded")
	}
}

func TestJiraListProjectIssues_Success(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search/jql" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("maxResults"); got != "50" {
			t.Fatalf("unexpected maxResults: %s", got)
		}
		if got := r.URL.Query().Get("fields"); got != "summary,status" {
			t.Fatalf("unexpected fields query: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issues":[
				{"id":"10011","key":"KAN-11","fields":{"summary":"First issue","status":{"name":"To Do"}}},
				{"id":"10012","key":"KAN-12","fields":{"summary":"Second issue","status":{"name":"Done"}}}
			]
		}`)
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListProjectIssues(context.Background(), cfg, "KAN", 50, "")
	if err != nil {
		t.Fatalf("list jira issues: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Key != "KAN-11" || items[0].Summary != "First issue" || items[0].Status != "To Do" {
		t.Fatalf("unexpected first issue payload: %#v", items[0])
	}
}

func TestJiraListProjectIssues_WithIssueTypeFilter(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search/jql" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		jql := r.URL.Query().Get("jql")
		if !strings.Contains(jql, `issuetype = "Epic"`) {
			t.Fatalf("expected issue type filter in jql, got: %s", jql)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issues":[
				{"id":"10021","key":"KAN-21","fields":{"summary":"Security epic","status":{"name":"To Do"}}}
			]
		}`)
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListProjectIssues(context.Background(), cfg, "KAN", 50, "Epic")
	if err != nil {
		t.Fatalf("list jira issues with issue type filter: %v", err)
	}
	if len(items) != 1 || items[0].Key != "KAN-21" {
		t.Fatalf("unexpected filtered issues payload: %#v", items)
	}
}

func TestJiraListProjectIssues_FallbackToLegacySearch(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	var calledJQL int
	var calledLegacy int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/search/jql":
			calledJQL++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		case "/rest/api/3/search":
			calledLegacy++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{
				"issues":[
					{"id":"10013","key":"KAN-13","fields":{"summary":"Legacy fallback issue","status":{"name":"To Do"}}}
				]
			}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListProjectIssues(context.Background(), cfg, "KAN", 50, "")
	if err != nil {
		t.Fatalf("list jira issues fallback: %v", err)
	}
	if calledJQL == 0 || calledLegacy == 0 {
		t.Fatalf("expected both jql and legacy endpoints to be called, got jql=%d legacy=%d", calledJQL, calledLegacy)
	}
	if len(items) != 1 || items[0].Key != "KAN-13" {
		t.Fatalf("unexpected fallback issues payload: %#v", items)
	}
}

func TestJiraListIssueTypes_FallbackToProjectStatusesWhenProjectDetailsDenied(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	var calledProjectDetails int
	var calledStatuses int
	var calledComponents int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/KAN":
			calledProjectDetails++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errorMessages":["forbidden"],"errors":{}}`)
		case "/rest/api/3/project/KAN/statuses":
			calledStatuses++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[
				{"id":"10001","name":"Task"},
				{"id":"10002","name":"Bug"}
			]`)
		case "/rest/api/3/project/KAN/components":
			calledComponents++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListIssueTypes(context.Background(), cfg, "KAN")
	if err != nil {
		t.Fatalf("list jira issue types fallback: %v", err)
	}
	if calledProjectDetails == 0 || calledStatuses == 0 {
		t.Fatalf("expected project details and statuses endpoints to be called, got details=%d statuses=%d", calledProjectDetails, calledStatuses)
	}
	_ = calledComponents
	if len(items) != 2 {
		t.Fatalf("expected 2 issue types, got %d", len(items))
	}
	if items[0].Name != "Task" || items[1].Name != "Bug" {
		t.Fatalf("unexpected issue types payload: %#v", items)
	}
}

func TestJiraListIssueTypes_FallbackParsesNestedIssueTypeFromProjectStatuses(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	var calledProjectDetails int
	var calledStatuses int
	var calledComponents int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/KAN":
			calledProjectDetails++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errorMessages":["forbidden"],"errors":{}}`)
		case "/rest/api/3/project/KAN/statuses":
			calledStatuses++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[
				{"issueType":{"id":"10001","name":"Task"},"statuses":[]},
				{"issueType":{"id":"10002","name":"Bug"},"statuses":[]}
			]`)
		case "/rest/api/3/project/KAN/components":
			calledComponents++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		case "/rest/api/3/search/jql", "/rest/api/3/search", "/rest/api/3/issuetype":
			t.Fatalf("unexpected endpoint call when statuses already provided issue types: %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListIssueTypes(context.Background(), cfg, "KAN")
	if err != nil {
		t.Fatalf("list jira issue types from nested statuses: %v", err)
	}
	if calledProjectDetails == 0 || calledStatuses == 0 {
		t.Fatalf("expected project details and statuses endpoints to be called, got details=%d statuses=%d", calledProjectDetails, calledStatuses)
	}
	_ = calledComponents
	if len(items) != 2 {
		t.Fatalf("expected 2 issue types, got %d", len(items))
	}
	if items[0].Name != "Task" || items[1].Name != "Bug" {
		t.Fatalf("unexpected issue types payload: %#v", items)
	}
}

func TestJiraListIssueTypes_FallbackToGlobalIssueTypesWhenProjectSpecificSourcesEmpty(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	var calledStatuses int
	var calledIssues int
	var calledGlobal int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/KAN":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"errorMessages":["forbidden"],"errors":{}}`)
		case "/rest/api/3/project/KAN/statuses":
			calledStatuses++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[]`)
		case "/rest/api/3/search/jql":
			calledIssues++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"issues":[]}`)
		case "/rest/api/3/issuetype":
			calledGlobal++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `[{"id":"10003","name":"Story"}]`)
		case "/rest/api/3/project/KAN/components":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListIssueTypes(context.Background(), cfg, "KAN")
	if err != nil {
		t.Fatalf("list jira issue types with global fallback: %v", err)
	}
	if calledStatuses == 0 || calledIssues == 0 || calledGlobal == 0 {
		t.Fatalf("expected statuses, issues and global issue type endpoints to be called, got statuses=%d issues=%d global=%d", calledStatuses, calledIssues, calledGlobal)
	}
	if len(items) != 1 || items[0].Name != "Story" {
		t.Fatalf("unexpected issue types payload: %#v", items)
	}
}

func TestJiraListProjectComponents_FallbackToDedicatedEndpointWhenMissingInProjectDetails(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	var calledProjectDetails int
	var calledComponents int
	var calledStatuses int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/project/KAN":
			calledProjectDetails++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"issueTypes":[{"id":"10001","name":"Task"}],"components":[]}`)
		case "/rest/api/3/project/KAN/components":
			calledComponents++
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"values":[{"id":"201","name":"Scanner"}]}`)
		case "/rest/api/3/project/KAN/statuses":
			calledStatuses++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"errorMessages":["not found"],"errors":{}}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	items, err := JiraListProjectComponents(context.Background(), cfg, "KAN")
	if err != nil {
		t.Fatalf("list jira components fallback: %v", err)
	}
	if calledProjectDetails == 0 || calledComponents == 0 {
		t.Fatalf("expected project details and components endpoints to be called, got details=%d components=%d", calledProjectDetails, calledComponents)
	}
	_ = calledStatuses
	if len(items) != 1 || items[0].Name != "Scanner" {
		t.Fatalf("unexpected components payload: %#v", items)
	}
}

func TestJiraGetIssueStatusSnapshot_Success(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")

	cfg, err := ParseJiraConnectorProfile([]byte(`{
		"baseUrl":"http://127.0.0.1:1",
		"authMode":"api_token",
		"email":"admin@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10,
		"deploymentMode":"cloud"
	}`))
	if err != nil {
		t.Fatalf("parse jira profile: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue/KAN-42" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("fields"); got != "status,resolution" {
			t.Fatalf("unexpected fields query: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"id":"10042",
			"key":"KAN-42",
			"fields":{
				"status":{"name":"Done","statusCategory":{"key":"done"}},
				"resolution":{"name":"Fixed"}
			}
		}`)
	}))
	defer srv.Close()
	cfg.BaseURL = srv.URL

	snapshot, err := JiraGetIssueStatusSnapshot(context.Background(), cfg, "KAN-42")
	if err != nil {
		t.Fatalf("jira issue status snapshot: %v", err)
	}
	if snapshot == nil {
		t.Fatalf("expected snapshot")
	}
	if snapshot.IssueID != "10042" || snapshot.IssueKey != "KAN-42" {
		t.Fatalf("unexpected issue identity: %#v", snapshot)
	}
	if snapshot.StatusName != "Done" || snapshot.StatusCategoryKey != "done" {
		t.Fatalf("unexpected status payload: %#v", snapshot)
	}
	if snapshot.ResolutionName != "Fixed" {
		t.Fatalf("unexpected resolution: %#v", snapshot)
	}
}

func TestJiraIssueIsClosed(t *testing.T) {
	if !jiraIssueIsClosed(&JiraIssueStatusSnapshot{StatusCategoryKey: "done"}) {
		t.Fatalf("expected done status category to be closed")
	}
	if !jiraIssueIsClosed(&JiraIssueStatusSnapshot{ResolutionName: "Fixed"}) {
		t.Fatalf("expected non-empty resolution to be closed when status/category are missing")
	}
	if !jiraIssueIsClosed(&JiraIssueStatusSnapshot{StatusName: "Resolved"}) {
		t.Fatalf("expected resolved status name to be closed")
	}
	if jiraIssueIsClosed(&JiraIssueStatusSnapshot{StatusName: "In Progress", StatusCategoryKey: "indeterminate"}) {
		t.Fatalf("did not expect in-progress issue to be closed")
	}
	if jiraIssueIsClosed(&JiraIssueStatusSnapshot{StatusName: "To Do", ResolutionName: "Fixed"}) {
		t.Fatalf("did not expect todo issue with stale resolution to be closed")
	}
}

func TestJiraIssueFields_AppliesEpicParentByDefault(t *testing.T) {
	fields := jiraIssueFields(
		JiraIssueUpsertPayload{
			ProjectKey: "SEC",
			IssueType:  "Task",
			Summary:    "test",
			IssueFields: map[string]any{
				jiraEpicIssueKeyField: "EPIC-123",
			},
		},
		3,
	)
	parent, ok := fields["parent"].(map[string]any)
	if !ok {
		t.Fatalf("expected parent field to be object, got %#v", fields["parent"])
	}
	if key, _ := parent["key"].(string); key != "EPIC-123" {
		t.Fatalf("expected parent.key=EPIC-123, got %#v", parent["key"])
	}
	if _, exists := fields[jiraEpicIssueKeyField]; exists {
		t.Fatalf("internal epic key marker leaked into Jira fields")
	}
}

func TestJiraIssueFields_AppliesCustomEpicField(t *testing.T) {
	fields := jiraIssueFields(
		JiraIssueUpsertPayload{
			ProjectKey: "SEC",
			IssueType:  "Task",
			Summary:    "test",
			IssueFields: map[string]any{
				jiraEpicIssueKeyField: "EPIC-456",
				jiraEpicFieldKeyField: "customfield_10014",
			},
		},
		3,
	)
	if got, _ := fields["customfield_10014"].(string); got != "EPIC-456" {
		t.Fatalf("expected customfield_10014=EPIC-456, got %#v", fields["customfield_10014"])
	}
	if _, exists := fields["parent"]; exists {
		t.Fatalf("did not expect parent field when custom epic field key is provided")
	}
	if _, exists := fields[jiraEpicFieldKeyField]; exists {
		t.Fatalf("internal epic field marker leaked into Jira fields")
	}
}

func TestJiraIssueFields_CreateModeWithoutEpicKey_DoesNotAttachParent(t *testing.T) {
	fields := jiraIssueFields(
		JiraIssueUpsertPayload{
			ProjectKey: "SEC",
			IssueType:  "Task",
			Summary:    "test",
			IssueFields: map[string]any{
				jiraEpicModeField:     "create",
				jiraEpicCreateType:    "Epic",
				jiraEpicCreateSummary: "CTWALL Epic {{product}}",
			},
		},
		3,
	)
	if _, exists := fields["parent"]; exists {
		t.Fatalf("did not expect parent field when create mode has no epic key yet")
	}
	if _, exists := fields[jiraEpicModeField]; exists {
		t.Fatalf("internal epic mode marker leaked into Jira fields")
	}
}

func TestJiraIssueFields_CreateModeWithEpicKey_AttachesParent(t *testing.T) {
	fields := jiraIssueFields(
		JiraIssueUpsertPayload{
			ProjectKey: "SEC",
			IssueType:  "Task",
			Summary:    "test",
			IssueFields: map[string]any{
				jiraEpicModeField:     "create",
				jiraEpicIssueKeyField: "EPIC-789",
			},
		},
		3,
	)
	parent, ok := fields["parent"].(map[string]any)
	if !ok {
		t.Fatalf("expected parent field to be object in create mode with epic key, got %#v", fields["parent"])
	}
	if key, _ := parent["key"].(string); key != "EPIC-789" {
		t.Fatalf("expected parent.key=EPIC-789, got %#v", parent["key"])
	}
}
