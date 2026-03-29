package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/core/auth"
	"backend/internal/core/malware"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestNewRouter(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: []byte("test-secret")}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/missing", nil)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}

func TestBuildRouteSpecsUniquePatternsAndAuthDefaults(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	specs := buildRouteSpecs(pgStore, Config{
		Auth: middleware.AuthConfig{
			JWTSecret: []byte("test-secret"),
		},
	})
	if len(specs) == 0 {
		t.Fatalf("expected non-empty route spec list")
	}

	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if _, exists := seen[spec.pattern]; exists {
			t.Fatalf("duplicate pattern found: %s", spec.pattern)
		}
		seen[spec.pattern] = struct{}{}
	}

	publicPatterns := map[string]struct{}{
		"GET /health":               {},
		"GET /api/v1/health":        {},
		"GET /docs":                 {},
		"GET /api/v1/openapi.yaml":  {},
		"POST /api/v1/auth/login":   {},
		"POST /api/v1/auth/refresh": {},
	}
	for _, spec := range specs {
		if !strings.Contains(spec.pattern, "/api/v1/") && spec.pattern != "GET /health" && spec.pattern != "GET /docs" {
			continue
		}
		if _, allowedPublic := publicPatterns[spec.pattern]; allowedPublic {
			continue
		}
		if len(spec.roles) == 0 {
			t.Fatalf("route should be authenticated but has no roles: %s", spec.pattern)
		}
	}
}

func TestBuildRouteSpecsSelectedPolicyMatrix(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	specs := buildRouteSpecs(pgStore, Config{
		Auth: middleware.AuthConfig{
			JWTSecret: []byte("test-secret"),
		},
	})

	type expectedPolicy struct {
		authRequired bool
		requireJSON  bool
	}
	expected := map[string]expectedPolicy{
		"GET /health":                      {authRequired: false, requireJSON: false},
		"GET /api/v1/health":               {authRequired: false, requireJSON: false},
		"POST /api/v1/auth/login":          {authRequired: false, requireJSON: true},
		"POST /api/v1/auth/logout":         {authRequired: true, requireJSON: false},
		"PUT /api/v1/alerting/dedup-rules": {authRequired: true, requireJSON: true},
		"PUT /api/v1/tests/{testId}/component-analysis/explorer/findings/triage": {authRequired: true, requireJSON: true},
		"GET /api/v1/component-analysis/explorer/findings":                       {authRequired: true, requireJSON: false},
	}

	byPattern := make(map[string]routeSpec, len(specs))
	for _, spec := range specs {
		byPattern[spec.pattern] = spec
	}

	for pattern, policy := range expected {
		spec, ok := byPattern[pattern]
		if !ok {
			t.Fatalf("missing route policy for %s", pattern)
		}
		if (len(spec.roles) > 0) != policy.authRequired {
			t.Fatalf("auth policy mismatch for %s", pattern)
		}
		if spec.requireJSON != policy.requireJSON {
			t.Fatalf("json policy mismatch for %s", pattern)
		}
	}
}

func TestNewRouterReturnsErrorWhenAuthMiddlewareConfigInvalid(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	if _, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{}}); err == nil {
		t.Fatalf("expected error for invalid auth middleware config")
	}
}

func TestNewRouterRegistersOSVRoutesWhenMalwareServiceConfigured(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	mux, err := NewRouter(pgStore, Config{
		Auth:    middleware.AuthConfig{JWTSecret: []byte("test-secret")},
		Malware: &malware.OSVSyncService{},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/explorer/osv/download_all", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected auth-protected OSV route to be registered, got %d", recorder.Code)
	}
}

func TestRouteRegistrarMustHandleReturnsErrorOnDuplicatePattern(t *testing.T) {
	t.Helper()

	registrar := routeRegistrar{
		mux:         http.NewServeMux(),
		auditWriter: nil,
		require: func(_ ...auth.Role) func(http.HandlerFunc) http.HandlerFunc {
			return func(next http.HandlerFunc) http.HandlerFunc { return next }
		},
		jsonHandler: func(next http.HandlerFunc) http.HandlerFunc { return next },
		seen:        make(map[string]struct{}),
	}

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}
	spec := routeSpec{
		pattern:   "GET /__duplicate-test",
		component: "handler.test.duplicate",
		handler:   handler,
	}
	if err := registrar.mustHandle(spec); err != nil {
		t.Fatalf("first mustHandle should pass: %v", err)
	}
	if err := registrar.mustHandle(spec); err == nil || !strings.Contains(err.Error(), "duplicate route registration") {
		t.Fatalf("expected duplicate route error, got: %v", err)
	}
}

func TestProjectReaderWithGlobalNoneCanReadProjectScopedEndpoints(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("test-secret")
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: secret}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	admin, err := pgStore.CreateUser(
		fmt.Sprintf("router-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Router Admin",
	)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	noneUser, err := pgStore.CreateUser(
		fmt.Sprintf("router-none-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"Project Reader",
	)
	if err != nil {
		t.Fatalf("create none user: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(admin.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: noneUser.ID, ProjectRole: store.ProjectRoleReader},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}
	group, err := pgStore.CreateGroupInProject(projectID, "Identity Group", "", admin.ID)
	if err != nil {
		t.Fatalf("create identity group: %v", err)
	}

	session, err := auth.NewSessionToken(noneUser.ID, auth.RoleNone, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	readCases := []string{
		"/api/v1/search?q=abc",
		"/api/v1/products?page=1&pageSize=20",
		"/api/v1/groups?page=1&pageSize=20",
		"/api/v1/scopes?page=1&pageSize=20",
		"/api/v1/tests?page=1&pageSize=20",
		"/api/v1/sboms?page=1&pageSize=20",
		"/api/v1/component-analysis/explorer/queue?page=1&pageSize=20",
		"/api/v1/component-analysis/explorer/findings?componentPurl=pkg:deb/debian/bsdutils@2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&epoch=1",
		"/api/v1/explorer/results?purl=pkg:deb/debian/bsdutils@2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&epoch=1",
		"/api/v1/explorer/findings?purl=pkg:deb/debian/bsdutils@2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12&epoch=1&page=1&pageSize=20",
		"/api/v1/explorer/sources",
	}
	for _, path := range readCases {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
		req.Header.Set("X-Project-ID", projectID.String())
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("expected 200 for %s, got %d", path, recorder.Code)
		}
	}

	// Identity -> members list should be readable for project READER.
	membersReq := httptest.NewRequest(http.MethodGet, "/api/v1/groups/"+group.ID.String()+"/members", nil)
	membersReq.SetPathValue("groupId", group.ID.String())
	membersReq.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	membersReq.Header.Set("X-Project-ID", projectID.String())
	membersRecorder := httptest.NewRecorder()
	mux.ServeHTTP(membersRecorder, membersReq)
	if membersRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for group members list, got %d", membersRecorder.Code)
	}

	// Reader must not be able to mutate identity data.
	createBody := `{"name":"Blocked For Reader"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	createReq.Header.Set("X-Project-ID", projectID.String())
	createRecorder := httptest.NewRecorder()
	mux.ServeHTTP(createRecorder, createReq)
	if createRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for group create by reader, got %d", createRecorder.Code)
	}
}

func TestGlobalNoneWithoutProjectMembershipIsForbiddenOnProjectScopedRead(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("test-secret")
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: secret}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	noneUser, err := pgStore.CreateUser(
		fmt.Sprintf("router-nomember-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"No Membership",
	)
	if err != nil {
		t.Fatalf("create none user: %v", err)
	}
	session, err := auth.NewSessionToken(noneUser.ID, auth.RoleNone, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=abc", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestProjectWriterWithGlobalNoneCanMutateProjectScopedEndpoints(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("test-secret")
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: secret}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	admin, err := pgStore.CreateUser(
		fmt.Sprintf("router-admin-write-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Router Admin",
	)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	writerUser, err := pgStore.CreateUser(
		fmt.Sprintf("router-writer-none-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"Project Writer",
	)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(admin.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: writerUser.ID, ProjectRole: store.ProjectRoleWriter},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}
	product, err := pgStore.CreateProductInProject(projectID, "Writer Product", "")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	scope, err := pgStore.CreateScope(product.ID, "Writer Scope", "")
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	testEntity, _, err := pgStore.EnsureTest(scope.ID, "Writer Test", "cyclonedx", "1.6")
	if err != nil {
		t.Fatalf("create test: %v", err)
	}

	session, err := auth.NewSessionToken(writerUser.ID, auth.RoleNone, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	request := func(method, path, contentType, body string, wantStatus int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
		req.Header.Set("X-Project-ID", projectID.String())
		if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete {
			req.AddCookie(&http.Cookie{Name: "__Host-XSRF-TOKEN", Value: "test-xsrf"})
			req.Header.Set("X-XSRF-TOKEN", "test-xsrf")
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		if recorder.Code != wantStatus {
			t.Fatalf("%s %s expected %d, got %d", method, path, wantStatus, recorder.Code)
		}
	}

	request(http.MethodPost, "/api/v1/groups", "application/json", `{"name":"Writer Group"}`, http.StatusCreated)
	request(http.MethodPost, "/api/v1/products", "application/json", `{"name":"Writer Product 2"}`, http.StatusCreated)
	request(http.MethodPost, "/api/v1/products/"+product.ID.String()+"/scopes", "application/json", `{"name":"Writer Scope 2"}`, http.StatusCreated)
	request(http.MethodPut, "/api/v1/alerting/dedup-rules", "application/json", `{"rules":[{"dedupScope":"GLOBAL","enabled":true}]}`, http.StatusOK)

	triageReq := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/tests/"+testEntity.ID.String()+"/component-analysis/explorer/findings/triage",
		strings.NewReader(`{"componentPurl":"pkg:pypi/a@1.0.0","malwarePurl":"pkg:pypi/mal@1.0.0","status":"RISK_ACCEPTED"}`),
	)
	triageReq.SetPathValue("testId", testEntity.ID.String())
	triageReq.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	triageReq.AddCookie(&http.Cookie{Name: "__Host-XSRF-TOKEN", Value: "test-xsrf"})
	triageReq.Header.Set("X-Project-ID", projectID.String())
	triageReq.Header.Set("X-XSRF-TOKEN", "test-xsrf")
	triageReq.Header.Set("Content-Type", "application/json")
	triageRecorder := httptest.NewRecorder()
	mux.ServeHTTP(triageRecorder, triageReq)
	if triageRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for malware triage upsert by project writer, got %d", triageRecorder.Code)
	}
}

func TestProjectScopedAuthorizationMatrix_CrossProjectDeniedAndAdminOnlyDenied(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("test-secret")
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: secret}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	admin, err := pgStore.CreateUser(
		fmt.Sprintf("router-admin-matrix-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Router Admin",
	)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	writerUser, err := pgStore.CreateUser(
		fmt.Sprintf("router-writer-matrix-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"Project Writer",
	)
	if err != nil {
		t.Fatalf("create writer: %v", err)
	}

	projectA, err := pgStore.CreateProject("Matrix Project A", "A", &admin.ID)
	if err != nil {
		t.Fatalf("create project A: %v", err)
	}
	projectB, err := pgStore.CreateProject("Matrix Project B", "B", &admin.ID)
	if err != nil {
		t.Fatalf("create project B: %v", err)
	}

	if err := pgStore.ReplaceProjectMembers(projectA.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: writerUser.ID, ProjectRole: store.ProjectRoleWriter},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project A members: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(projectB.ID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &admin.ID); err != nil {
		t.Fatalf("replace project B members: %v", err)
	}

	session, err := auth.NewSessionToken(writerUser.ID, auth.RoleNone, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	// Writer in project A can read project-scoped data.
	reqAllowed := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=matrix", nil)
	reqAllowed.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	reqAllowed.Header.Set("X-Project-ID", projectA.ID.String())
	recAllowed := httptest.NewRecorder()
	mux.ServeHTTP(recAllowed, reqAllowed)
	if recAllowed.Code != http.StatusOK {
		t.Fatalf("expected 200 for writer read in own project, got %d", recAllowed.Code)
	}

	// Cross-project access is denied.
	reqDenied := httptest.NewRequest(http.MethodGet, "/api/v1/search?q=matrix", nil)
	reqDenied.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	reqDenied.Header.Set("X-Project-ID", projectB.ID.String())
	recDenied := httptest.NewRecorder()
	mux.ServeHTTP(recDenied, reqDenied)
	if recDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-project read, got %d", recDenied.Code)
	}

	// Project writer cannot access global admin settings.
	reqAdminOnly := httptest.NewRequest(http.MethodGet, "/api/v1/admin/settings/general", nil)
	reqAdminOnly.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	reqAdminOnly.Header.Set("X-Project-ID", projectA.ID.String())
	recAdminOnly := httptest.NewRecorder()
	mux.ServeHTTP(recAdminOnly, reqAdminOnly)
	if recAdminOnly.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for admin-only settings, got %d", recAdminOnly.Code)
	}
}

func TestProjectAdminWithGlobalNoneCanManageProjectMembers(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	secret := []byte("test-secret")
	mux, err := NewRouter(pgStore, Config{Auth: middleware.AuthConfig{JWTSecret: secret}})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}

	rootAdmin, err := pgStore.CreateUser(
		fmt.Sprintf("router-root-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Root Admin",
	)
	if err != nil {
		t.Fatalf("create root admin: %v", err)
	}
	projectAdmin, err := pgStore.CreateUser(
		fmt.Sprintf("router-project-admin-none-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"Project Admin",
	)
	if err != nil {
		t.Fatalf("create project admin: %v", err)
	}
	targetReader, err := pgStore.CreateUser(
		fmt.Sprintf("router-target-reader-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleNone),
		string(auth.AccountTypeUser),
		"Target Reader",
	)
	if err != nil {
		t.Fatalf("create target user: %v", err)
	}

	project, err := pgStore.CreateProject("Project Admin Matrix", "matrix", &rootAdmin.ID)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(project.ID, []store.ProjectMemberAssignment{
		{UserID: rootAdmin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: projectAdmin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: targetReader.ID, ProjectRole: store.ProjectRoleReader},
	}, &rootAdmin.ID); err != nil {
		t.Fatalf("seed project members: %v", err)
	}

	session, err := auth.NewSessionToken(projectAdmin.ID, auth.RoleNone, time.Minute, secret, "")
	if err != nil {
		t.Fatalf("new session token: %v", err)
	}

	body := fmt.Sprintf(`{"members":[{"userId":"%s","projectRole":"ADMIN"},{"userId":"%s","projectRole":"WRITER"}]}`,
		projectAdmin.ID.String(),
		targetReader.ID.String(),
	)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+project.ID.String()+"/members", strings.NewReader(body))
	req.SetPathValue("projectId", project.ID.String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project-ID", project.ID.String())
	req.Header.Set("X-XSRF-TOKEN", "test-xsrf")
	req.AddCookie(&http.Cookie{Name: "__Host-CTWALL_SESSION", Value: session})
	req.AddCookie(&http.Cookie{Name: "__Host-XSRF-TOKEN", Value: "test-xsrf"})

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for project-admin members update, got %d", recorder.Code)
	}
}
