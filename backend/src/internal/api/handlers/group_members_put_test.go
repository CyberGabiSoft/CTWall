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

func createUserForGroupTest(t *testing.T, st store.Store, role auth.Role, name string) uuid.UUID {
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
	return user.ID
}

func TestPutGroupMembersHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutGroupMembersHandler(pgStore, nil)

	ownerID := createUserForGroupTest(t, pgStore, auth.RoleAdmin, "owner")
	editorID := createUserForGroupTest(t, pgStore, auth.RoleWriter, "editor")

	projects, err := pgStore.ListProjectsForUser(ownerID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: ownerID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: editorID, ProjectRole: store.ProjectRoleWriter},
	}, &ownerID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}
	group, err := pgStore.CreateGroupInProject(projectID, "Security Team", "", ownerID)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	payload := groupMembersSetRequest{
		Members: []groupMemberRequest{
			{UserID: ownerID.String(), Role: "OWNER"},
			{UserID: editorID.String(), Role: "EDITOR"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/"+group.ID.String()+"/members", bytes.NewReader(body))
	req.SetPathValue("groupId", group.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, ownerID, "owner@example.com", auth.RoleAdmin))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}

	members, err := pgStore.ListGroupMembers(projectID, group.ID)
	if err != nil {
		t.Fatalf("list group members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(members))
	}
}

func TestPutGroupMembersHandlerForbiddenForNonOwner(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutGroupMembersHandler(pgStore, nil)

	ownerID := createUserForGroupTest(t, pgStore, auth.RoleAdmin, "owner")
	writerID := createUserForGroupTest(t, pgStore, auth.RoleWriter, "writer")

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
	group, err := pgStore.CreateGroupInProject(projectID, "Blue Team", "", ownerID)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	payload := groupMembersSetRequest{
		Members: []groupMemberRequest{
			{UserID: ownerID.String(), Role: "OWNER"},
			{UserID: writerID.String(), Role: "EDITOR"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/"+group.ID.String()+"/members", bytes.NewReader(body))
	req.SetPathValue("groupId", group.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, writerID, "writer@example.com", auth.RoleWriter))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}

func TestPutGroupMembersHandlerCreatorProtected(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutGroupMembersHandler(pgStore, nil)

	creatorID := createUserForGroupTest(t, pgStore, auth.RoleAdmin, "creator")
	otherOwnerID := createUserForGroupTest(t, pgStore, auth.RoleAdmin, "other")

	projects, err := pgStore.ListProjectsForUser(creatorID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	if err := pgStore.ReplaceProjectMembers(projectID, []store.ProjectMemberAssignment{
		{UserID: creatorID, ProjectRole: store.ProjectRoleAdmin},
		{UserID: otherOwnerID, ProjectRole: store.ProjectRoleAdmin},
	}, &creatorID); err != nil {
		t.Fatalf("replace project members: %v", err)
	}
	group, err := pgStore.CreateGroupInProject(projectID, "Owners", "", creatorID)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, err := pgStore.CreateProductWithOwnerGroup(projectID, "Product A", "", &group.ID, creatorID); err != nil {
		t.Fatalf("create product with owner group: %v", err)
	}

	payload := groupMembersSetRequest{
		Members: []groupMemberRequest{
			{UserID: otherOwnerID.String(), Role: "OWNER"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/groups/"+group.ID.String()+"/members", bytes.NewReader(body))
	req.SetPathValue("groupId", group.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, creatorID, "creator@example.com", auth.RoleAdmin))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", recorder.Code)
	}
}
