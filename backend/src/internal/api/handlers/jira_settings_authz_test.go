package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func createUserForJiraSettingsAuthzTest(t *testing.T, st store.Store, role auth.Role, name string) (uuid.UUID, string) {
	t.Helper()
	user, err := st.CreateUser(
		fmt.Sprintf("%s-%s@example.com", name, uuid.NewString()),
		"hash",
		string(role),
		string(auth.AccountTypeUser),
		name,
	)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user.ID, user.Email
}

func TestPutProductJiraSettings_AllowsProjectAdminWithoutOwnerRole(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutProductJiraSettingsHandler(pgStore, nil)

	ownerID, _ := createUserForJiraSettingsAuthzTest(t, pgStore, auth.RoleAdmin, "owner")
	projectAdminID, projectAdminEmail := createUserForJiraSettingsAuthzTest(t, pgStore, auth.RoleWriter, "project-admin")

	projects, err := pgStore.ListProjectsForUser(ownerID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID

	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: ownerID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: projectAdminID, ProjectRole: store.ProjectRoleAdmin},
	}, &ownerID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	ownerGroup, err := pgStore.CreateGroupInProject(projectID, "Owners", "", ownerID)
	if err != nil {
		t.Fatalf("create owner group: %v", err)
	}
	product, err := pgStore.CreateProductWithOwnerGroup(projectID, "Svc", "", &ownerGroup.ID, ownerID)
	if err != nil {
		t.Fatalf("create product: %v", err)
	}

	payload := jiraEntitySettingsRequest{
		IsEnabled:             true,
		JiraProjectKey:        "KAN",
		IssueType:             "Task",
		TicketSummaryTemplate: "CTWall {{product}}",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/data/products/"+product.ID.String()+"/jira/settings", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, projectAdminID, projectAdminEmail, auth.RoleWriter))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPutProductJiraSettings_RejectsWriterWithoutOwnerRole(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutProductJiraSettingsHandler(pgStore, nil)

	ownerID, _ := createUserForJiraSettingsAuthzTest(t, pgStore, auth.RoleAdmin, "owner")
	writerID, writerEmail := createUserForJiraSettingsAuthzTest(t, pgStore, auth.RoleWriter, "writer")

	projects, err := pgStore.ListProjectsForUser(ownerID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID

	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: ownerID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: writerID, ProjectRole: store.ProjectRoleWriter},
	}, &ownerID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}

	ownerGroup, err := pgStore.CreateGroupInProject(projectID, "Owners", "", ownerID)
	if err != nil {
		t.Fatalf("create owner group: %v", err)
	}
	product, err := pgStore.CreateProductWithOwnerGroup(projectID, "Svc", "", &ownerGroup.ID, ownerID)
	if err != nil {
		t.Fatalf("create product: %v", err)
	}

	payload := jiraEntitySettingsRequest{
		IsEnabled:             true,
		JiraProjectKey:        "KAN",
		IssueType:             "Task",
		TicketSummaryTemplate: "CTWall {{product}}",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/data/products/"+product.ID.String()+"/jira/settings", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, withUser(req, writerID, writerEmail, auth.RoleWriter))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}
