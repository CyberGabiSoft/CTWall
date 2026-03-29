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

func withUser(req *http.Request, id uuid.UUID, email string, role auth.Role) *http.Request {
	return req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
		ID:          id,
		Email:       email,
		Role:        role,
		AccountType: auth.AccountTypeUser,
	}))
}

func TestCreateGroupHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := CreateGroupHandler(pgStore)

	user, err := pgStore.CreateUser(
		fmt.Sprintf("groups-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Groups Admin",
	)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewBufferString("bad"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ := json.Marshal(map[string]string{"name": "  "})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]string{"name": "Team One"})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/groups", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", recorder.Code)
	}
}

func TestListGroupsAndMembersReaderAccess(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	admin, err := pgStore.CreateUser(
		fmt.Sprintf("owner-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Owner",
	)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	reader, err := pgStore.CreateUser(
		fmt.Sprintf("reader-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleReader),
		string(auth.AccountTypeUser),
		"Reader",
	)
	if err != nil {
		t.Fatalf("create reader: %v", err)
	}

	projects, err := pgStore.ListProjectsForUser(admin.ID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	group, err := pgStore.CreateGroupInProject(projectID, "Blue Team", "", admin.ID)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: admin.ID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: reader.ID, ProjectRole: store.ProjectRoleReader},
	}, &admin.ID); err != nil {
		t.Fatalf("replace members: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	listReq.Header.Set(projectHeaderName, projectID.String())
	listRecorder := httptest.NewRecorder()
	ListGroupsHandler(pgStore).ServeHTTP(listRecorder, withUser(listReq, reader.ID, reader.Email, auth.RoleReader))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for list groups, got %d", listRecorder.Code)
	}

	membersReq := httptest.NewRequest(http.MethodGet, "/api/v1/groups/"+group.ID.String()+"/members", nil)
	membersReq.SetPathValue("groupId", group.ID.String())
	membersReq.Header.Set(projectHeaderName, projectID.String())
	membersRecorder := httptest.NewRecorder()
	ListGroupMembersHandler(pgStore).ServeHTTP(membersRecorder, withUser(membersReq, reader.ID, reader.Email, auth.RoleReader))
	if membersRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for list group members, got %d", membersRecorder.Code)
	}
}

func TestListGroupMembersHandlerBadAndNotFound(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := ListGroupMembersHandler(pgStore)
	user, err := pgStore.CreateUser(
		fmt.Sprintf("members-admin-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Admin",
	)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups/bad/members", nil)
	req.SetPathValue("groupId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/groups/missing/members", nil)
	req.SetPathValue("groupId", uuid.NewString())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, user.ID, user.Email, auth.RoleAdmin))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}
}
