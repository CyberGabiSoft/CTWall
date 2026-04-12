package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"
)

func TestListAlertDetectionModesHandler_RequiresAuth(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := ListAlertDetectionModesHandler(st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerting/detection-modes", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}

func TestListAlertDetectionModesHandler_Defaults(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := ListAlertDetectionModesHandler(st)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerting/detection-modes", nil)
	req, _, projectID := withAuthedAdminAndProject(t, st, req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload alertDetectionModesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Items) != 2 {
		t.Fatalf("expected 2 detection modes, got %d", len(payload.Items))
	}

	var smart *models.AlertDetectionMode
	var prefix *models.AlertDetectionMode
	for i := range payload.Items {
		item := payload.Items[i]
		if item.ProjectID != projectID {
			t.Fatalf("unexpected project id in response")
		}
		switch item.Mode {
		case string(store.AlertDetectionModePURLVersionSmart):
			smart = &item
		case string(store.AlertDetectionModePURLContainsPrefix):
			prefix = &item
		}
	}
	if smart == nil || prefix == nil {
		t.Fatalf("expected both detection mode rows, got %+v", payload.Items)
	}
	if !smart.Enabled || smart.Severity != "ERROR" {
		t.Fatalf("unexpected smart defaults: enabled=%v severity=%q", smart.Enabled, smart.Severity)
	}
	if prefix.Enabled || prefix.Severity != "WARN" {
		t.Fatalf("unexpected prefix defaults: enabled=%v severity=%q", prefix.Enabled, prefix.Severity)
	}
}

func TestPutAlertDetectionModesHandler_ReplaceAndList(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	putHandler := PutAlertDetectionModesHandler(st, nil)
	listHandler := ListAlertDetectionModesHandler(st)

	body := map[string]any{
		"modes": []map[string]any{
			{
				"mode":     "PURL_VERSION_SMART",
				"enabled":  true,
				"severity": "INFO",
			},
			{
				"mode":     "PURL_CONTAINS_PREFIX",
				"enabled":  true,
				"severity": "WARNING",
			},
		},
	}
	raw, _ := json.Marshal(body)

	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/alerting/detection-modes", bytes.NewReader(raw))
	putReq, _, _ = withAuthedAdminAndProject(t, st, putReq)
	putRec := httptest.NewRecorder()
	putHandler.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on put, got %d; body=%s", putRec.Code, putRec.Body.String())
	}
	var putPayload alertDetectionModesResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &putPayload); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if len(putPayload.Items) != 2 {
		t.Fatalf("expected 2 items on put, got %d", len(putPayload.Items))
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/alerting/detection-modes", nil)
	listReq, _, _ = withAuthedAdminAndProject(t, st, listReq)
	listRec := httptest.NewRecorder()
	listHandler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on list, got %d", listRec.Code)
	}
	var listPayload alertDetectionModesResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listPayload.Items) != 2 {
		t.Fatalf("expected 2 items in list, got %d", len(listPayload.Items))
	}
}

func TestPutAlertDetectionModesHandler_InvalidMode(t *testing.T) {
	st, _ := tests.NewPostgresTestStore(t)
	handler := PutAlertDetectionModesHandler(st, nil)

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/alerting/detection-modes",
		bytes.NewBufferString(`{"modes":[{"mode":"bad","enabled":true,"severity":"ERROR"}]}`),
	)
	req, _, _ = withAuthedAdminAndProject(t, st, req)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid mode payload, got %d", rec.Code)
	}
}
