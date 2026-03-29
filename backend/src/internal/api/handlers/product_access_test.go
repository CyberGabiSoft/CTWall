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

func createUserForProductAccessTest(t *testing.T, st store.Store, role auth.Role, name string) uuid.UUID {
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

func TestGetProductAccessHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetProductAccessHandler(pgStore)

	ownerID := createUserForProductAccessTest(t, pgStore, auth.RoleAdmin, "owner")

	projects, err := pgStore.ListProjectsForUser(ownerID, true)
	if err != nil || len(projects) == 0 {
		t.Fatalf("list projects: %v", err)
	}
	projectID := projects[0].ID
	ownerGroup, err := pgStore.CreateGroupInProject(projectID, "Owners", "", ownerID)
	if err != nil {
		t.Fatalf("create owner group: %v", err)
	}
	product, err := pgStore.CreateProductWithOwnerGroup(projectID, "App", "", &ownerGroup.ID, ownerID)
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	viewGroup, err := pgStore.CreateGroupInProject(projectID, "Viewers", "", ownerID)
	if err != nil {
		t.Fatalf("create view group: %v", err)
	}
	if err := pgStore.ReplaceProductGroupGrants(projectID, product.ID, []store.ProductGroupGrantAssignment{
		{GroupID: viewGroup.ID, Role: store.ProductGroupGrantRoleViewer},
	}, ownerID); err != nil {
		t.Fatalf("replace product grants: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+product.ID.String()+"/access", nil)
	req.SetPathValue("productId", product.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, ownerID, "owner@example.com", auth.RoleAdmin))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response productAccessResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.OwnerGroupID != ownerGroup.ID.String() {
		t.Fatalf("expected owner group %s, got %s", ownerGroup.ID, response.OwnerGroupID)
	}
	if len(response.Grants) != 1 || response.Grants[0].GroupID != viewGroup.ID.String() || response.Grants[0].Role != "VIEWER" {
		t.Fatalf("unexpected grants payload: %+v", response.Grants)
	}
}

func TestPutProductAccessHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := PutProductAccessHandler(pgStore, nil)

	ownerID := createUserForProductAccessTest(t, pgStore, auth.RoleAdmin, "owner")
	writerID := createUserForProductAccessTest(t, pgStore, auth.RoleWriter, "writer")

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
	product, err := pgStore.CreateProductWithOwnerGroup(projectID, "Service", "", &ownerGroup.ID, ownerID)
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	editGroup, err := pgStore.CreateGroupInProject(projectID, "Editors", "", ownerID)
	if err != nil {
		t.Fatalf("create editor group: %v", err)
	}

	payload := productAccessSetRequest{
		Grants: []productAccessGrantRequest{
			{GroupID: editGroup.ID.String(), Role: "EDITOR"},
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/products/"+product.ID.String()+"/access", bytes.NewReader(body))
	req.SetPathValue("productId", product.ID.String())
	req.Header.Set(projectHeaderName, projectID.String())
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withUser(req, ownerID, "owner@example.com", auth.RoleAdmin))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	writerReq := httptest.NewRequest(http.MethodPut, "/api/v1/products/"+product.ID.String()+"/access", bytes.NewReader(body))
	writerReq.SetPathValue("productId", product.ID.String())
	writerReq.Header.Set(projectHeaderName, projectID.String())
	writerRecorder := httptest.NewRecorder()
	handler.ServeHTTP(writerRecorder, withUser(writerReq, writerID, "writer@example.com", auth.RoleWriter))
	if writerRecorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner writer, got %d", writerRecorder.Code)
	}

	badPayload := productAccessSetRequest{
		Grants: []productAccessGrantRequest{
			{GroupID: ownerGroup.ID.String(), Role: "VIEWER"},
		},
	}
	badBody, _ := json.Marshal(badPayload)
	badReq := httptest.NewRequest(http.MethodPut, "/api/v1/products/"+product.ID.String()+"/access", bytes.NewReader(badBody))
	badReq.SetPathValue("productId", product.ID.String())
	badReq.Header.Set(projectHeaderName, projectID.String())
	badRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badRecorder, withUser(badReq, ownerID, "owner@example.com", auth.RoleAdmin))
	if badRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for owner group in explicit grants, got %d", badRecorder.Code)
	}
}
