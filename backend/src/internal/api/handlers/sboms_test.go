package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"backend/internal/store"
	"backend/internal/tests"

	"github.com/google/uuid"
)

func TestListSbomsHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testCyclone, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "1.6")
	testSpdx, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "spdx", "2.3")

	if _, err := pgStore.StoreSbom("sha1", []byte("{}"), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	if _, err := pgStore.StoreSbom("sha2", []byte("{}"), "spdx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}

	first, _ := pgStore.AddRevision(testCyclone.ID, store.RevisionInput{SbomSha256: "sha1", SbomProducer: "syft", Tags: []string{"blue"}})
	time.Sleep(10 * time.Millisecond)
	second, _ := pgStore.AddRevision(testSpdx.ID, store.RevisionInput{SbomSha256: "sha2", SbomProducer: "grype", Tags: []string{"red"}})

	handler := ListSbomsHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?page=0", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?productId=bad", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?productId="+product.ID.String()+"&tag=blue", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var items []sbomListItem
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].RevisionID != first.ID {
		t.Fatalf("unexpected revision id")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?tags=red", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 1 || items[0].RevisionID != second.ID {
		t.Fatalf("unexpected tag filter result")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?sbomStandard=spdx", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 1 || items[0].RevisionID != second.ID {
		t.Fatalf("unexpected sbomType filter result")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?scopeId="+scope.ID.String(), nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?productId="+uuid.New().String(), nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected productId mismatch to filter out items")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?scopeId="+uuid.New().String(), nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected scopeId mismatch to filter out items")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?testId="+uuid.New().String(), nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected testId mismatch to filter out items")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetScopeMissing: true}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected items to be skipped when scope missing")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetTestMissing: true}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected items to be skipped when test missing")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetProductMissing: true}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	items = nil
	if err := json.NewDecoder(recorder.Body).Decode(&items); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected items to be skipped when product missing")
	}

	if hasTag([]string{"blue"}, "") {
		t.Fatalf("expected empty tag to be false")
	}
	if hasTag([]string{"blue"}, "red") {
		t.Fatalf("expected missing tag to be false")
	}
}

func TestDownloadSbomHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	if _, err := pgStore.StoreSbom("sha-json", []byte("data"), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, _ := pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha-json"})

	handler := DownloadSbomHandler(pgStore)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/bad/download", nil)
	req.SetPathValue("revisionId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/missing/download", nil)
	req.SetPathValue("revisionId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	DownloadSbomHandler(tests.StoreWrapper{Store: pgStore, GetSbomErr: store.ErrNotFound}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected content type")
	}
	if recorder.Header().Get("Content-Disposition") == "" {
		t.Fatalf("expected content disposition")
	}

	content := []byte("data")
	if _, err := pgStore.StoreSbom("sha-empty", content, "", "", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, _ = pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha-empty"})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("expected default content type")
	}

	if _, err := pgStore.StoreSbom("sha-gz", []byte("gzip"), "cyclonedx", "application/json", true); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, _ = pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha-gz"})
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("expected gzip content type")
	}
}

func TestDownloadSbomHandlerErrors(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	if _, err := pgStore.StoreSbom("sha1", []byte("data"), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	revision, _ := pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder := httptest.NewRecorder()
	DownloadSbomHandler(tests.StoreWrapper{Store: pgStore, GetRevisionErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms/id/download", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	DownloadSbomHandler(tests.StoreWrapper{Store: pgStore, GetSbomErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestListSbomsHandlerErrors(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	if _, err := pgStore.StoreSbom("sha1", []byte("data"), "cyclonedx", "application/json", false); err != nil {
		t.Fatalf("store sbom: %v", err)
	}
	_, _ = pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha1"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder := httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, ListAllRevisionsErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetTestErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetScopeErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms", nil)
	recorder = httptest.NewRecorder()
	ListSbomsHandler(tests.StoreWrapper{Store: pgStore, GetProductErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestDeleteSbomHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")
	_, _ = pgStore.StoreSbom("sha1", []byte("data"), "cyclonedx", "application/json", false)
	revision, _ := pgStore.AddRevision(testItem.ID, store.RevisionInput{SbomSha256: "sha1"})

	handler := DeleteSbomHandler(pgStore)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/bad", nil)
	req.SetPathValue("revisionId", "bad")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/missing", nil)
	req.SetPathValue("revisionId", uuid.New().String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/id", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	DeleteSbomHandler(tests.StoreWrapper{Store: pgStore, DeleteRevisionErr: errors.New("boom")}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/sboms/id", nil)
	req.SetPathValue("revisionId", revision.ID.String())
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}

func TestParseSbomFilters(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms?scopeId=bad", nil)
	if _, err := parseSbomFilters(req); err == nil {
		t.Fatalf("expected scopeId parse error")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?testId=bad", nil)
	if _, err := parseSbomFilters(req); err == nil {
		t.Fatalf("expected testId parse error")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?sbomType=unknown", nil)
	if _, err := parseSbomFilters(req); err == nil {
		t.Fatalf("expected sbomType validation error")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?tag="+strings.Repeat("a", maxTagLength+1), nil)
	if _, err := parseSbomFilters(req); err == nil {
		t.Fatalf("expected tag validation error")
	}

	productID := uuid.New().String()
	scopeID := uuid.New().String()
	testID := uuid.New().String()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sboms?productId="+productID+"&scopeId="+scopeID+"&testId="+testID+"&sbomStandard=cyclonedx&sbomSpecVersion=1.6&sbomProducer=syft&tag=blue", nil)
	filters, err := parseSbomFilters(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if filters.productID == nil || filters.scopeID == nil || filters.testID == nil {
		t.Fatalf("expected ids to be parsed")
	}
	if filters.sbomStandard != "cyclonedx" || filters.sbomSpecVersion != "1.6" || filters.sbomProducer != "syft" || filters.tag != "blue" {
		t.Fatalf("unexpected filters: %+v", filters)
	}
}
