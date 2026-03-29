package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	payload := map[string]string{"ok": "true"}
	writeJSON(recorder, http.StatusOK, payload)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", got)
	}

	var decoded map[string]string
	if err := json.NewDecoder(recorder.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded["ok"] != "true" {
		t.Fatalf("unexpected payload: %v", decoded)
	}

	recorder = httptest.NewRecorder()
	writeJSON(recorder, http.StatusNoContent, nil)
	if recorder.Body.Len() != 0 {
		t.Fatalf("expected empty body")
	}
}

func TestWriteProblem(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)

	recorder := httptest.NewRecorder()
	writeProblem(recorder, req, http.StatusBadRequest, "Bad", "details", nil)
	var problem ProblemDetails
	if err := json.NewDecoder(recorder.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.ErrorID != "" {
		t.Fatalf("expected no error id for 4xx")
	}

	recorder = httptest.NewRecorder()
	writeProblem(recorder, req, http.StatusInternalServerError, "Internal", "details", nil)
	if err := json.NewDecoder(recorder.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.ErrorID == "" {
		t.Fatalf("expected error id for 5xx")
	}

	recorder = httptest.NewRecorder()
	writeProblem(recorder, req, http.StatusInternalServerError, "Internal", "details", errors.New("boom"))
	if err := json.NewDecoder(recorder.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.ErrorID == "" {
		t.Fatalf("expected error id for 5xx with error")
	}
}
