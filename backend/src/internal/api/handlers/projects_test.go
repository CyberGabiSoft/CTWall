package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestUpdateProjectHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := UpdateProjectHandler(pgStore, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/projects/bad", strings.NewReader(`{"name":"Alpha"}`))
	req.SetPathValue("projectId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	project, err := pgStore.CreateProject("Alpha", "First", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+project.ID.String(), strings.NewReader(`{"name":"   ","description":"x"}`))
	req.SetPathValue("projectId", project.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid name, got %d", recorder.Code)
	}

	missingID := uuid.New()
	req = httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+missingID.String(), strings.NewReader(`{"name":"Missing"}`))
	req.SetPathValue("projectId", missingID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	other, err := pgStore.CreateProject("Beta", "Second", nil)
	if err != nil {
		t.Fatalf("create second project: %v", err)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+other.ID.String(), strings.NewReader(`{"name":"Alpha"}`))
	req.SetPathValue("projectId", other.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+project.ID.String(), strings.NewReader(`{"name":"Alpha Updated","description":"Updated description"}`))
	req.SetPathValue("projectId", project.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var updated models.Project
	if err := decodeJSONResponse(recorder, &updated); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if updated.ID != project.ID || updated.Name != "Alpha Updated" || updated.Description != "Updated description" {
		t.Fatalf("unexpected payload: %+v", updated)
	}

	persisted, err := pgStore.GetProject(project.ID)
	if err != nil {
		t.Fatalf("load updated project: %v", err)
	}
	if persisted.Name != "Alpha Updated" || persisted.Description != "Updated description" {
		t.Fatalf("project not updated in db: %+v", persisted)
	}
}

func TestProjectMembersHandlersUseExplicitProjectRolePayload(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	getHandler := ListProjectMembersHandler(pgStore)
	putHandler := ReplaceProjectMembersHandler(pgStore, nil)

	projectAdmin, err := pgStore.CreateUser(
		fmt.Sprintf("project-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Project Admin",
	)
	if err != nil {
		t.Fatalf("create project admin: %v", err)
	}
	projectWriter, err := pgStore.CreateUser(
		fmt.Sprintf("project-writer-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Project Writer",
	)
	if err != nil {
		t.Fatalf("create project writer: %v", err)
	}
	projectReader, err := pgStore.CreateUser(
		fmt.Sprintf("project-reader-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleReader),
		string(auth.AccountTypeUser),
		"Project Reader",
	)
	if err != nil {
		t.Fatalf("create project reader: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(projectAdmin.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: projectAdmin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: projectWriter.ID, ProjectRole: store.ProjectRoleWriter},
		{UserID: projectReader.ID, ProjectRole: store.ProjectRoleReader},
	}, &projectAdmin.ID); err != nil {
		t.Fatalf("seed project members: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/members", nil)
	getReq.SetPathValue("projectId", projectID.String())
	getRecorder := httptest.NewRecorder()
	getHandler.ServeHTTP(getRecorder, withUser(getReq, projectAdmin.ID, projectAdmin.Email, auth.RoleWriter))
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for project admin list, got %d", getRecorder.Code)
	}
	var members []models.ProjectMember
	if err := decodeJSONResponse(getRecorder, &members); err != nil {
		t.Fatalf("decode members response: %v", err)
	}
	if len(members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(members))
	}

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/members", nil)
	forbiddenReq.SetPathValue("projectId", projectID.String())
	forbiddenRecorder := httptest.NewRecorder()
	getHandler.ServeHTTP(forbiddenRecorder, withUser(forbiddenReq, projectWriter.ID, projectWriter.Email, auth.RoleWriter))
	if forbiddenRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-project-admin list, got %d", forbiddenRecorder.Code)
	}

	payload := projectMembersRequest{
		Members: []projectMemberRequest{
			{UserID: projectAdmin.ID.String(), ProjectRole: "ADMIN"},
			{UserID: projectWriter.ID.String(), ProjectRole: "READER"},
			{UserID: projectReader.ID.String(), ProjectRole: "WRITER"},
		},
	}
	body, _ := json.Marshal(payload)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+projectID.String()+"/members", strings.NewReader(string(body)))
	putReq.SetPathValue("projectId", projectID.String())
	putRecorder := httptest.NewRecorder()
	putHandler.ServeHTTP(putRecorder, withUser(putReq, projectAdmin.ID, projectAdmin.Email, auth.RoleWriter))
	if putRecorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for valid replace, got %d", putRecorder.Code)
	}

	updatedMembers, err := pgStore.ListProjectMembers(projectID)
	if err != nil {
		t.Fatalf("list updated members: %v", err)
	}
	byID := make(map[uuid.UUID]string, len(updatedMembers))
	for _, member := range updatedMembers {
		byID[member.ID] = member.ProjectRole
	}
	if byID[projectWriter.ID] != store.ProjectRoleReader || byID[projectReader.ID] != store.ProjectRoleWriter {
		t.Fatalf("unexpected updated roles: %+v", byID)
	}

	invalidRoleBody := `{"members":[{"userId":"` + projectAdmin.ID.String() + `","projectRole":"BAD"}]}`
	invalidReq := httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+projectID.String()+"/members", strings.NewReader(invalidRoleBody))
	invalidReq.SetPathValue("projectId", projectID.String())
	invalidRecorder := httptest.NewRecorder()
	putHandler.ServeHTTP(invalidRecorder, withUser(invalidReq, projectAdmin.ID, projectAdmin.Email, auth.RoleWriter))
	if invalidRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid projectRole, got %d", invalidRecorder.Code)
	}

	noAdminBody := `{"members":[{"userId":"` + projectWriter.ID.String() + `","projectRole":"WRITER"},{"userId":"` + projectReader.ID.String() + `","projectRole":"READER"}]}`
	noAdminReq := httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+projectID.String()+"/members", strings.NewReader(noAdminBody))
	noAdminReq.SetPathValue("projectId", projectID.String())
	noAdminRecorder := httptest.NewRecorder()
	putHandler.ServeHTTP(noAdminRecorder, withUser(noAdminReq, projectAdmin.ID, projectAdmin.Email, auth.RoleWriter))
	if noAdminRecorder.Code != http.StatusConflict {
		t.Fatalf("expected 409 when removing last ADMIN, got %d", noAdminRecorder.Code)
	}
}

func TestListProjectMembersHandlerAllowsNullFullName(t *testing.T) {
	pgStore, db := tests.NewPostgresTestStore(t)
	getHandler := ListProjectMembersHandler(pgStore)

	projectAdmin, err := pgStore.CreateUser(
		fmt.Sprintf("project-admin-null-fullname-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Project Admin",
	)
	if err != nil {
		t.Fatalf("create project admin: %v", err)
	}
	member, err := pgStore.CreateUser(
		fmt.Sprintf("project-member-null-fullname-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleReader),
		string(auth.AccountTypeUser),
		"Project Member",
	)
	if err != nil {
		t.Fatalf("create project member: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(projectAdmin.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: projectAdmin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: member.ID, ProjectRole: store.ProjectRoleReader},
	}, &projectAdmin.ID); err != nil {
		t.Fatalf("seed project members: %v", err)
	}

	if _, err := db.Exec(`UPDATE users SET full_name = NULL WHERE id = $1`, member.ID); err != nil {
		t.Fatalf("set null full_name: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+projectID.String()+"/members", nil)
	getReq.SetPathValue("projectId", projectID.String())
	getRecorder := httptest.NewRecorder()
	getHandler.ServeHTTP(getRecorder, withUser(getReq, projectAdmin.ID, projectAdmin.Email, auth.RoleWriter))
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for project members list with null full_name, got %d", getRecorder.Code)
	}

	var members []models.ProjectMember
	if err := decodeJSONResponse(getRecorder, &members); err != nil {
		t.Fatalf("decode members response: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
	for _, item := range members {
		if item.ID == member.ID && item.FullName != "" {
			t.Fatalf("expected empty fullName for NULL db value, got %q", item.FullName)
		}
	}
}

func TestReplaceProjectMembersHandlerProtectsProductCreatorMembership(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	putHandler := ReplaceProjectMembersHandler(pgStore, nil)

	actor, err := pgStore.CreateUser(
		fmt.Sprintf("actor-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Actor",
	)
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	creator, err := pgStore.CreateUser(
		fmt.Sprintf("creator-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Creator",
	)
	if err != nil {
		t.Fatalf("create creator: %v", err)
	}
	backupAdmin, err := pgStore.CreateUser(
		fmt.Sprintf("backup-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleWriter),
		string(auth.AccountTypeUser),
		"Backup",
	)
	if err != nil {
		t.Fatalf("create backup admin: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(actor.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: actor.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: creator.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: backupAdmin.ID, ProjectRole: store.ProjectRoleAdmin},
	}, &actor.ID); err != nil {
		t.Fatalf("seed project members: %v", err)
	}

	ownerGroup, err := pgStore.CreateGroupInProject(projectID, "Creator Owners", "", creator.ID)
	if err != nil {
		t.Fatalf("create owner group: %v", err)
	}
	if _, err := pgStore.CreateProductWithOwnerGroup(projectID, "Protected Product", "", &ownerGroup.ID, creator.ID); err != nil {
		t.Fatalf("create product with creator: %v", err)
	}

	payload := `{"members":[{"userId":"` + actor.ID.String() + `","projectRole":"ADMIN"},{"userId":"` + backupAdmin.ID.String() + `","projectRole":"ADMIN"}]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/projects/"+projectID.String()+"/members", strings.NewReader(payload))
	req.SetPathValue("projectId", projectID.String())
	recorder := httptest.NewRecorder()
	putHandler.ServeHTTP(recorder, withUser(req, actor.ID, actor.Email, auth.RoleWriter))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409 when removing product creator from project, got %d", recorder.Code)
	}
}

func decodeJSONResponse[T any](recorder *httptest.ResponseRecorder, target *T) error {
	return json.Unmarshal(recorder.Body.Bytes(), target)
}
