package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/tests"
)

func TestDashboardOverviewHandlerUnauthorized(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestDashboardOverviewHandlerInvalidRange(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?range=2d", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDashboardOverviewHandlerProjectForbidden(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	project, err := pgStore.CreateProject("Dashboard Forbidden Project", "", nil)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	user, err := pgStore.CreateUser("reader-dashboard@example.com", "hash", string(auth.RoleReader), string(auth.AccountTypeUser), "Reader")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	req.Header.Set(projectHeaderName, project.ID.String())
	req = req.WithContext(auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Email:       user.Email,
		Role:        auth.RoleReader,
		AccountType: auth.AccountTypeUser,
	}))
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestDashboardOverviewHandlerSuccess(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?range=7d&topN=10", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload struct {
		Scope     string `json:"scope"`
		ProjectID string `json:"projectId"`
		Range     string `json:"range"`
		Data      struct {
			ProjectCount int `json:"projectCount"`
			TopN         int `json:"topN"`
			KPIs         struct {
				SnapshotTests int `json:"snapshotTests"`
			} `json:"kpis"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Scope != "project" {
		t.Fatalf("expected project scope, got %q", payload.Scope)
	}
	if payload.ProjectID == "" {
		t.Fatalf("expected non-empty projectId")
	}
	if payload.Range != "7d" {
		t.Fatalf("expected range 7d, got %q", payload.Range)
	}
	if payload.Data.TopN != 10 {
		t.Fatalf("expected topN=10, got %d", payload.Data.TopN)
	}
	if payload.Data.ProjectCount != 1 {
		t.Fatalf("expected exactly one project in scope, got %d", payload.Data.ProjectCount)
	}
}

func TestDashboardTopNAllowsLargeValues(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?topN=999", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload struct {
		Data struct {
			TopN int `json:"topN"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.TopN != 999 {
		t.Fatalf("expected topN to keep requested value, got %d", payload.Data.TopN)
	}
}

func TestDashboardOverviewHandlerInvalidProjectHeader(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	req.Header.Set(projectHeaderName, "bad-uuid")
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDashboardOverviewHandlerInvalidTopN(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?topN=-1", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestDashboardOverviewHandlerAllTopN(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview?topN=ALL", nil)
	rec := httptest.NewRecorder()
	DashboardOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload struct {
		Data struct {
			TopN int `json:"topN"`
		} `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Data.TopN != 0 {
		t.Fatalf("expected topN=0 for ALL, got %d", payload.Data.TopN)
	}
}
