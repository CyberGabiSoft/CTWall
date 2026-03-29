package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/alerting"
	"backend/internal/core/auth"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestGetJiraMetadataProjectsHandler_ProductReaderAccess(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataProjectsHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	reader, err := pgStore.CreateUser("jira-meta-reader-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleReader), string(auth.AccountTypeUser), "Reader")
	if err != nil {
		t.Fatalf("create reader user: %v", err)
	}

	project, err := pgStore.CreateProject("Jira Metadata Project "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: reader.ID, ProjectRole: store.ProjectRoleReader},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project/search" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"startAt":0,"maxResults":100,"total":1,"isLast":true,"values":[{"id":"10000","key":"APP","name":"Application"}]}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/projects", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, reader.ID, reader.Email, auth.RoleReader))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool             `json:"fromCache"`
		Items     []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 metadata project, got %d", len(payload.Items))
	}
	if payload.Items[0]["key"] != "APP" {
		t.Fatalf("expected project key APP, got %#v", payload.Items[0]["key"])
	}
}

func TestGetJiraMetadataProjectsHandler_ForbiddenWithoutProjectAccess(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataProjectsHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	outsider, err := pgStore.CreateUser("jira-meta-outsider-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleReader), string(auth.AccountTypeUser), "Outsider")
	if err != nil {
		t.Fatalf("create outsider user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Forbidden "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, []byte(`{
		"baseUrl":"https://jira.example.com",
		"authMode":"api_token",
		"email":"jira@example.com",
		"apiToken":"token",
		"requestTimeoutSeconds":10
	}`), true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/projects", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, outsider.ID, outsider.Email, auth.RoleReader))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestGetJiraMetadataProjectsHandler_ScopeMismatchReturnsEmpty200(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataProjectsHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Scope Mismatch "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project/search" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorMessages":["scope does not match"],"errors":{}}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/projects", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                           `json:"fromCache"`
		Items     []alerting.JiraMetadataProject `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 0 {
		t.Fatalf("expected 0 metadata projects, got %d", len(payload.Items))
	}
}

func TestGetJiraMetadataProjectsHandler_UnauthorizedReturnsEmpty200(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataProjectsHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Unauthorized "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project/search" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorMessages":["unauthorized"],"errors":{}}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/projects", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                           `json:"fromCache"`
		Items     []alerting.JiraMetadataProject `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 0 {
		t.Fatalf("expected 0 metadata projects, got %d", len(payload.Items))
	}
}

func TestGetJiraMetadataIssueTypesHandler_NotFoundReturnsEmpty200(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataIssueTypesHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata IssueTypes NotFound "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/project/KAN" && r.URL.Path != "/rest/api/2/project/KAN" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessages":["No project could be found with key 'KAN'."],"errors":{}}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/issue-types?projectKey=KAN", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                             `json:"fromCache"`
		Items     []alerting.JiraMetadataIssueType `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 0 {
		t.Fatalf("expected 0 issue types, got %d", len(payload.Items))
	}
}

func TestGetJiraMetadataIssuesHandler_Success(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataIssuesHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Issues "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search/jql" && r.URL.Path != "/rest/api/3/search" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("maxResults"); got != "50" {
			t.Fatalf("unexpected maxResults query: %s", got)
		}
		_, _ = w.Write([]byte(`{
			"issues":[
				{"id":"10011","key":"KAN-11","fields":{"summary":"First issue","status":{"name":"To Do"}}}
			]
		}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/issues?projectKey=KAN", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                         `json:"fromCache"`
		Items     []alerting.JiraMetadataIssue `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(payload.Items))
	}
	if payload.Items[0].Key != "KAN-11" {
		t.Fatalf("expected KAN-11, got %q", payload.Items[0].Key)
	}
}

func TestGetJiraMetadataPrioritiesHandler_ForbiddenReturnsDefault200(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataPrioritiesHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Priorities Forbidden "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/priority" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errorMessages":["forbidden"],"errors":{}}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/priorities", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                            `json:"fromCache"`
		Items     []alerting.JiraMetadataPriority `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) == 0 {
		t.Fatalf("expected non-empty default priorities fallback")
	}
	foundHigh := false
	for _, item := range payload.Items {
		if item.Name == "High" {
			foundHigh = true
			break
		}
	}
	if !foundHigh {
		t.Fatalf("expected default priorities to include High")
	}
}

func TestGetJiraMetadataPrioritiesHandler_UnauthorizedReturnsDefault200(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataPrioritiesHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Priorities Unauthorized "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/priority" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorMessages":["unauthorized"],"errors":{}}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/priorities", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                            `json:"fromCache"`
		Items     []alerting.JiraMetadataPriority `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) == 0 {
		t.Fatalf("expected non-empty default priorities fallback")
	}
}

func TestGetJiraMetadataIssueFieldsHandler_Success(t *testing.T) {
	t.Setenv("ALERTING_ALLOW_HTTP_TARGETS", "true")
	t.Setenv("ALERTING_ALLOW_LOCALHOST_TARGETS", "true")
	t.Setenv("APP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetJiraMetadataIssueFieldsHandler(pgStore)

	admin, err := pgStore.CreateUser("jira-meta-admin-"+uuid.NewString()+"@example.com", "hash", string(auth.RoleAdmin), string(auth.AccountTypeUser), "Admin")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	project, err := pgStore.CreateProject("Jira Metadata Issue Fields "+uuid.NewString(), "", &admin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	jiraSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/issue/createmeta" {
			t.Fatalf("unexpected Jira metadata path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("projectKeys"); got != "KAN" {
			t.Fatalf("unexpected projectKeys query: %s", got)
		}
		if got := r.URL.Query().Get("issuetypeIds"); got != "10001" {
			t.Fatalf("unexpected issuetypeIds query: %s", got)
		}
		_, _ = w.Write([]byte(`{
			"projects":[
				{
					"key":"KAN",
					"issuetypes":[
						{
							"id":"10001",
							"name":"Bug",
							"fields":{
								"summary":{"required":true,"name":"Summary","schema":{"type":"string"}},
								"customfield_10010":{
									"required":true,
									"name":"Environment",
									"schema":{"type":"option"},
									"allowedValues":[{"id":"20001","name":"Prod"}]
								}
							}
						}
					]
				}
			]
		}`))
	}))
	defer jiraSrv.Close()

	cfgJSON := []byte(`{
		"baseUrl":"` + jiraSrv.URL + `",
		"authMode":"api_token",
		"email":"jira-reader@example.com",
		"apiToken":"secret-token",
		"requestTimeoutSeconds":10
	}`)
	if _, err := pgStore.UpsertProjectConnectorConfig(project.ID, store.ConnectorTypeJira, cfgJSON, true); err != nil {
		t.Fatalf("upsert jira connector: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/data/jira/metadata/issue-fields?projectKey=KAN&issueTypeId=10001", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, admin.ID, admin.Email, auth.RoleAdmin))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		FromCache bool                              `json:"fromCache"`
		Items     []alerting.JiraMetadataIssueField `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 1 {
		t.Fatalf("expected 1 required issue field, got %d", len(payload.Items))
	}
	if payload.Items[0].Key != "customfield_10010" {
		t.Fatalf("expected customfield_10010, got %q", payload.Items[0].Key)
	}
	if payload.Items[0].InputType != "single_select" {
		t.Fatalf("expected single_select, got %q", payload.Items[0].InputType)
	}
}
