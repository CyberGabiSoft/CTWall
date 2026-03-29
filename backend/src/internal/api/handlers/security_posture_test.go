package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/tests"
)

func TestSecurityPostureOverviewHandlerUnauthorized(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/posture/overview", nil)
	rec := httptest.NewRecorder()
	SecurityPostureOverviewHandler(pgStore).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestSecurityPostureOverviewHandlerInvalidBucket(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/posture/overview?bucket=month", nil)
	rec := httptest.NewRecorder()
	SecurityPostureOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestSecurityPostureOverviewHandlerSuccess(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/posture/overview?range=7d&topN=9&bucket=week", nil)
	rec := httptest.NewRecorder()
	SecurityPostureOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var payload struct {
		Scope     string `json:"scope"`
		ProjectID string `json:"projectId"`
		Range     string `json:"range"`
		Bucket    string `json:"bucket"`
		Data      struct {
			ProjectID string `json:"projectId"`
			TopN      int    `json:"topN"`
			Bucket    string `json:"bucket"`
			Score     struct {
				Value int `json:"value"`
			} `json:"score"`
			KPIs struct {
				OsvSyncStatus string `json:"osvSyncStatus"`
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
	if payload.Bucket != "week" {
		t.Fatalf("expected bucket week, got %q", payload.Bucket)
	}
	if payload.Data.ProjectID != payload.ProjectID {
		t.Fatalf("expected matching project ids, got header=%q data=%q", payload.ProjectID, payload.Data.ProjectID)
	}
	if payload.Data.TopN != 9 {
		t.Fatalf("expected topN=9, got %d", payload.Data.TopN)
	}
	if payload.Data.Bucket != "week" {
		t.Fatalf("expected data bucket week, got %q", payload.Data.Bucket)
	}
	if payload.Data.Score.Value < 0 || payload.Data.Score.Value > 100 {
		t.Fatalf("expected score in 0-100 range, got %d", payload.Data.Score.Value)
	}
	if payload.Data.KPIs.OsvSyncStatus == "" {
		t.Fatalf("expected osvSyncStatus to be set")
	}
}

func TestSecurityPostureOverviewHandlerAllTopN(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/posture/overview?topN=ALL", nil)
	rec := httptest.NewRecorder()
	SecurityPostureOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
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

func TestSecurityPostureOverviewHandlerAllowsLargeTopN(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/posture/overview?topN=999", nil)
	rec := httptest.NewRecorder()
	SecurityPostureOverviewHandler(pgStore).ServeHTTP(rec, withAuthedRequest(t, pgStore, req))
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
