package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"backend/internal/models"
	"backend/internal/tests"
)

func TestMatchesQuery(t *testing.T) {
	if !matchesQuery("Payment Gateway", "pay") {
		t.Fatalf("expected substring match")
	}
	if matchesQuery("Payment", "oops") {
		t.Fatalf("expected mismatch")
	}
	if !matchesQuery("PaymentGateway", "pay*gate") {
		t.Fatalf("expected wildcard match")
	}
	if matchesQuery("PaymentGateway", "pay*missing") {
		t.Fatalf("expected wildcard mismatch")
	}
	if !matchesQuery("PaymentGateway", "*pay*gate*") {
		t.Fatalf("expected wildcard with empty parts")
	}
}

func TestSearchHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	_, _, _ = pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")

	handler := SearchHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/search", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?q="+strings.Repeat("a", maxSearchQueryRunes+1), nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?q=pay", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := response["products"]; !ok {
		t.Fatalf("expected products key")
	}
	if _, ok := response["scopes"]; !ok {
		t.Fatalf("expected scopes key")
	}
	if _, ok := response["tests"]; !ok {
		t.Fatalf("expected tests key")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?q=pay", nil)
	recorder = httptest.NewRecorder()
	SearchHandler(tests.StoreWrapper{Store: pgStore, ListProductsErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?q=pay", nil)
	recorder = httptest.NewRecorder()
	SearchHandler(tests.StoreWrapper{Store: pgStore, ListAllScopesErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/search?q=pay", nil)
	recorder = httptest.NewRecorder()
	SearchHandler(tests.StoreWrapper{Store: pgStore, ListAllTestsErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestFilterHelpers(t *testing.T) {
	products := []models.Product{{Name: "Alpha"}, {Name: "Beta"}}
	if got := filterProducts(products, "alpha"); len(got) != 1 || got[0].Name != "Alpha" {
		t.Fatalf("unexpected product filter: %v", got)
	}
	if got := filterProducts(products, "zzz"); len(got) != 0 {
		t.Fatalf("expected no product matches")
	}

	scopes := []models.Scope{{Name: "Core"}, {Name: "Payments"}}
	if got := filterScopes(scopes, "pay"); len(got) != 1 || got[0].Name != "Payments" {
		t.Fatalf("unexpected scope filter: %v", got)
	}
	if got := filterScopes(scopes, "none"); len(got) != 0 {
		t.Fatalf("expected no scope matches")
	}

	tests := []models.Test{{Name: "Gateway"}, {Name: "Payments"}}
	if got := filterTests(tests, "gate"); len(got) != 1 || got[0].Name != "Gateway" {
		t.Fatalf("unexpected test filter: %v", got)
	}
	if got := filterTests(tests, "none"); len(got) != 0 {
		t.Fatalf("expected no test matches")
	}
}
