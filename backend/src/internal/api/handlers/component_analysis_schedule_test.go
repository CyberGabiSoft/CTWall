package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/tests"
)

func TestGetComponentAnalysisMalwareScheduleHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := GetComponentAnalysisMalwareScheduleHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/component-analysis/explorer/schedule", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}

func TestUpdateComponentAnalysisMalwareScheduleHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := UpdateComponentAnalysisMalwareScheduleHandler(pgStore, nil, nil)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/component-analysis/explorer/schedule", bytes.NewBufferString("bad"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ := json.Marshal(map[string]any{})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/component-analysis/explorer/schedule", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]any{"enabled": true, "interval": "0s"})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/component-analysis/explorer/schedule", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]any{"interval": "bogus"})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/component-analysis/explorer/schedule", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	body, _ = json.Marshal(map[string]any{"enabled": false})
	req = httptest.NewRequest(http.MethodPatch, "/api/v1/component-analysis/explorer/schedule", bytes.NewReader(body))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
}
