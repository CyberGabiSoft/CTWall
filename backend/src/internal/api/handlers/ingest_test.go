package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backend/internal/models"
	"backend/internal/store"
	"backend/internal/tests"

	"backend/internal/sbom"

	"github.com/google/uuid"
)

func newMultipartRequest(t *testing.T, fields map[string]string, tags []string, tagKey string, includeFile bool, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatalf("write field: %v", err)
		}
	}
	for _, tag := range tags {
		if err := writer.WriteField(tagKey, tag); err != nil {
			t.Fatalf("write tag: %v", err)
		}
	}
	if includeFile {
		part, err := writer.CreateFormFile("sbom_file", filename)
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := part.Write(content); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

var fixtureComponentCounts = map[string]int{
	filepath.Join("sbom_syft_cyclonedx", "out_cyclonedx_syft_1_6.json"): 3107,
	filepath.Join("sbom_trivy_cyclonedx", "trivy_out.json"):             121,
}

const (
	sbomTypeCycloneDX = `{"standard":"cyclonedx","specVersion":"1.6"}`
	sbomTypeUnknown   = `{"standard":"cyclonedx","specVersion":"unknown"}`
)

func loadSBOMFixture(t *testing.T, relativePath ...string) []byte {
	t.Helper()
	root := repoRoot(t)
	parts := append([]string{root, "sboms"}, relativePath...)
	path := filepath.Join(parts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sbom fixture: %v", err)
	}
	return data
}

func expectedFixtureComponentCount(t *testing.T, relativePath ...string) int {
	t.Helper()
	key := filepath.Join(relativePath...)
	count, ok := fixtureComponentCounts[key]
	if !ok {
		t.Fatalf("missing fixture count for %s", key)
	}
	return count
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for i := 0; i < 10; i++ {
		if info, err := os.Stat(filepath.Join(current, "sboms")); err == nil && info.IsDir() {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	t.Fatalf("sboms directory not found from %s", wd)
	return ""
}

func expectedComponentCount(t *testing.T, data []byte) int {
	t.Helper()
	var doc struct {
		Components []json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	return len(doc.Components)
}

func newRequestWithForm(values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Form = values
	req.PostForm = values
	return req
}

type failingSbomStore struct {
	store.Store
	err error
}

func (s failingSbomStore) StoreSbom(_ string, _ []byte, _ string, _ string, _ bool) (*store.SbomObject, error) {
	return nil, s.err
}

type failingStatusStore struct {
	store.Store
	failStatus string
}

func (s failingStatusStore) UpdateIngestJobStatus(id uuid.UUID, status string, errorMessage string) error {
	if status == s.failStatus {
		return errors.New("status failure")
	}
	return s.Store.UpdateIngestJobStatus(id, status, errorMessage)
}

func TestExtractTags(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if got := extractTags(req); got != nil {
		t.Fatalf("expected nil tags")
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.MultipartForm = &multipart.Form{Value: map[string][]string{"tags": {" alpha ", ""}}}
	if got := extractTags(req); len(got) != 1 || got[0] != "alpha" {
		t.Fatalf("unexpected tags: %v", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.MultipartForm = &multipart.Form{Value: map[string][]string{"tags[]": {"beta"}}}
	if got := extractTags(req); len(got) != 1 || got[0] != "beta" {
		t.Fatalf("unexpected tags: %v", got)
	}
}

func TestIsGzipPayload(t *testing.T) {
	if isGzipPayload([]byte("hi")) {
		t.Fatalf("expected non-gzip")
	}
	data := tests.GzipData(t, []byte("payload"))
	if !isGzipPayload(data) {
		t.Fatalf("expected gzip")
	}
}

func TestCountComponents(t *testing.T) {
	fixtures := []struct {
		name string
		path []string
	}{
		{name: "syft-cyclonedx", path: []string{"sbom_syft_cyclonedx", "out_cyclonedx_syft_1_6.json"}},
		{name: "trivy-cyclonedx", path: []string{"sbom_trivy_cyclonedx", "trivy_out.json"}},
	}
	for _, fixture := range fixtures {
		data := loadSBOMFixture(t, fixture.path...)
		expected := expectedFixtureComponentCount(t, fixture.path...)
		actual := expectedComponentCount(t, data)
		if actual != expected {
			t.Fatalf("fixture %s component count changed: expected %d, got %d", fixture.name, expected, actual)
		}
		if got := countComponents(data, false); got != expected {
			t.Fatalf("expected %d components for %s, got %d", expected, fixture.name, got)
		}
		t.Logf("fixture %s components=%d", fixture.name, expected)
	}
	if got := countComponents(tests.SBOMInvalidJSON, false); got != 0 {
		t.Fatalf("expected 0 for invalid JSON, got %d", got)
	}
	if got := countComponents([]byte(`{"components":{}}`), false); got != 0 {
		t.Fatalf("expected 0 for invalid components array, got %d", got)
	}
	if got := countComponents([]byte(`{"packages":{}}`), false); got != 0 {
		t.Fatalf("expected 0 for invalid packages array, got %d", got)
	}
	if got := countComponents([]byte("not-gzip"), true); got != 0 {
		t.Fatalf("expected 0 for invalid gzip, got %d", got)
	}
	trivyData := loadSBOMFixture(t, "sbom_trivy_cyclonedx", "trivy_out.json")
	expectedTrivy := expectedFixtureComponentCount(t, "sbom_trivy_cyclonedx", "trivy_out.json")
	gzipData := tests.GzipData(t, trivyData)
	if got := countComponents(gzipData, true); got != expectedTrivy {
		t.Fatalf("expected gzip payload to match components count, got %d", got)
	}

}

func TestEnsureScopeAndTest(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")

	if _, err := ensureScope(pgStore, product, ""); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("expected scope name error")
	}

	wrapped := tests.StoreWrapper{Store: pgStore, EnsureScopeErr: errors.New("boom")}
	if _, err := ensureScope(wrapped, product, "Scope"); err == nil || err.status != http.StatusInternalServerError {
		t.Fatalf("expected scope internal error")
	}

	missingProduct := &models.Product{ID: uuid.New()}
	if _, err := ensureScope(pgStore, missingProduct, "Scope"); err == nil || err.status != http.StatusNotFound {
		t.Fatalf("expected scope not found")
	}

	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	if _, err := ensureTest(pgStore, scope, "", "cyclonedx", "unknown"); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("expected test name error")
	}

	wrapped = tests.StoreWrapper{Store: pgStore, EnsureTestErr: errors.New("boom")}
	if _, err := ensureTest(wrapped, scope, "Gateway", "cyclonedx", "unknown"); err == nil || err.status != http.StatusInternalServerError {
		t.Fatalf("expected test internal error")
	}

	missingScope := &models.Scope{ID: uuid.New()}
	if _, err := ensureTest(pgStore, missingScope, "Gateway", "cyclonedx", "unknown"); err == nil || err.status != http.StatusNotFound {
		t.Fatalf("expected test not found")
	}
}

func TestResolveEntities(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	product, _ := pgStore.CreateProduct("Alpha", "")
	scope, _, _ := pgStore.EnsureScope(product.ID, "Payments", "")
	testItem, _, _ := pgStore.EnsureTest(scope.ID, "Gateway", "cyclonedx", "unknown")

	form := url.Values{"testId": {"bad"}}
	req := newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("expected bad testId")
	}

	form = url.Values{"testId": {uuid.New().String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusNotFound {
		t.Fatalf("expected test not found")
	}

	form = url.Values{"testId": {testItem.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetTestErr: errors.New("boom")}); err == nil || err.detail != "Failed to load test." {
		t.Fatalf("expected test load error")
	}

	form = url.Values{"testId": {testItem.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetScopeMissing: true}); err == nil || err.detail != "Scope not found for test." {
		t.Fatalf("expected scope not found")
	}

	form = url.Values{"testId": {testItem.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetProductMissing: true}); err == nil || err.detail != "Product not found for test." {
		t.Fatalf("expected product not found")
	}

	form = url.Values{"testId": {testItem.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetScopeErr: errors.New("boom")}); err == nil || err.detail != "Failed to load scope." {
		t.Fatalf("expected scope load error")
	}

	form = url.Values{"testId": {testItem.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetProductErr: errors.New("boom")}); err == nil || err.detail != "Failed to load product for test." {
		t.Fatalf("expected product load error for test")
	}

	form = url.Values{"scopeId": {"bad"}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("expected bad scopeId")
	}

	form = url.Values{"scopeId": {uuid.New().String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusNotFound {
		t.Fatalf("expected scope not found")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetScopeErr: errors.New("boom")}); err == nil || err.detail != "Failed to load scope." {
		t.Fatalf("expected scope load error")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetProductMissing: true}); err == nil || err.detail != "Product not found for scope." {
		t.Fatalf("expected product not found for scope")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetProductErr: errors.New("boom")}); err == nil || err.detail != "Failed to load product for scope." {
		t.Fatalf("expected product load error for scope")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "productId": {uuid.New().String()}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Provided productId does not match scopeId." {
		t.Fatalf("expected productId mismatch")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "product": {"Other"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Provided product name does not match scopeId." {
		t.Fatalf("expected product name mismatch")
	}

	form = url.Values{"scopeId": {scope.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Field 'test' or 'testId' is required." {
		t.Fatalf("expected test name required")
	}

	form = url.Values{"productId": {"bad"}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("expected bad productId")
	}

	form = url.Values{"productId": {uuid.New().String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.status != http.StatusNotFound {
		t.Fatalf("expected product not found")
	}

	form = url.Values{"productId": {product.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, GetProductErr: errors.New("boom")}); err == nil || err.detail != "Failed to load product." {
		t.Fatalf("expected product load error")
	}

	form = url.Values{"product": {"NewProd"}, "scope": {"Payments"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, EnsureProductErr: errors.New("boom")}); err == nil || err.detail != "Failed to resolve product." {
		t.Fatalf("expected product resolve error")
	}

	form = url.Values{"product": {"NewProd"}, "scope": {"Payments"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err != nil {
		t.Fatalf("expected product creation path, got %v", err)
	}

	form = url.Values{"testId": {testItem.ID.String()}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	productOut, scopeOut, testOut, err := resolveEntities(req, pgStore)
	if err != nil {
		t.Fatalf("expected testId lookup success, got %v", err)
	}
	if testOut.ID != testItem.ID || scopeOut.ID != scope.ID || productOut.ID != product.ID {
		t.Fatalf("unexpected entity resolution for testId")
	}

	form = url.Values{"scopeId": {scope.ID.String()}, "test": {"NewTest"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err != nil {
		t.Fatalf("expected scopeId path success, got %v", err)
	}

	form = url.Values{"productId": {product.ID.String()}, "scope": {"Core"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err != nil {
		t.Fatalf("expected productId path success, got %v", err)
	}

	form = url.Values{"product": {"Alpha"}, "scope": {"Core"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, EnsureScopeErr: errors.New("boom")}); err == nil || err.detail != "Failed to resolve scope." {
		t.Fatalf("expected scope resolve error")
	}

	form = url.Values{"product": {"Alpha"}, "scope": {"Core"}, "test": {"Gateway"}, "sbomType": {sbomTypeUnknown}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, tests.StoreWrapper{Store: pgStore, EnsureTestErr: errors.New("boom")}); err == nil || err.detail != "Failed to resolve test." {
		t.Fatalf("expected test resolve error")
	}

	form = url.Values{"product": {"Alpha"}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Field 'scope' or 'scopeId' is required." {
		t.Fatalf("expected scope required error")
	}

	form = url.Values{"product": {"Alpha"}, "scope": {"Payments"}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Field 'test' or 'testId' is required." {
		t.Fatalf("expected test required error")
	}

	form = url.Values{"productId": {product.ID.String()}}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Field 'scope' or 'scopeId' is required." {
		t.Fatalf("expected scope required error")
	}

	form = url.Values{}
	req = newRequestWithForm(form)
	if _, _, _, err := resolveEntities(req, pgStore); err == nil || err.detail != "Field 'product' or 'productId' is required." {
		t.Fatalf("expected product required")
	}
}

func TestIngestHandler(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := IngestHandler(pgStore, IngestConfig{EnqueueWorkers: 1})
	sbomData := loadSBOMFixture(t, "sbom_trivy_cyclonedx", "trivy_out.json")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("nope"))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", false, "", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", nil)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	origReadAll := readAll
	readAll = func(_ io.Reader) ([]byte, error) {
		return nil, errors.New("boom")
	}
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	readAll = origReadAll
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway", "metadataJson": "{bad"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway", "sbomType": "unknown"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	tooManyTags := make([]string, maxTagCount+1)
	for i := range tooManyTags {
		tooManyTags[i] = "alpha"
	}
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, tooManyTags, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	longName := strings.Repeat("a", maxNameLength+1)
	req = newMultipartRequest(t, map[string]string{"product": longName, "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	req = newMultipartRequest(t, map[string]string{}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", recorder.Code)
	}

	wrapped := tests.StoreWrapper{Store: pgStore, CreateIngestJobErr: errors.New("boom")}
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	IngestHandler(wrapped, IngestConfig{EnqueueWorkers: 1}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	wrapped = tests.StoreWrapper{Store: pgStore, UpdateIngestStatusErr: errors.New("boom")}
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	IngestHandler(wrapped, IngestConfig{EnqueueWorkers: 1}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	wrapped = tests.StoreWrapper{Store: pgStore, AddRevisionErr: errors.New("boom")}
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	IngestHandler(wrapped, IngestConfig{EnqueueWorkers: 1}).ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	errorStore := failingSbomStore{Store: pgStore, err: errors.New("sbom failure")}
	handler = IngestHandler(errorStore, IngestConfig{EnqueueWorkers: 1})
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	handler = IngestHandler(failingStatusStore{Store: errorStore, failStatus: store.IngestStatusFailed}, IngestConfig{EnqueueWorkers: 1})
	req = newMultipartRequest(t, map[string]string{"product": "Alpha", "scope": "Payments", "test": "Gateway"}, nil, "tags", true, "sbom.json", sbomData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}

	handler = IngestHandler(pgStore, IngestConfig{EnqueueWorkers: 1})
	gzipData := tests.GzipData(t, sbomData)
	req = newMultipartRequest(t, map[string]string{
		"product":      "Alpha",
		"scope":        "Payments",
		"test":         "Gateway",
		"metadataJson": "{\"owner\":\"team\"}",
		"sbomType":     sbomTypeCycloneDX,
	}, []string{"alpha", "beta"}, "tags[]", true, "sbom.json", gzipData)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	expected := expectedFixtureComponentCount(t, "sbom_trivy_cyclonedx", "trivy_out.json")
	if resp["componentsImportedCount"].(float64) != float64(expected) {
		t.Fatalf("unexpected components count: %v", resp["componentsImportedCount"])
	}
	t.Logf("ingest componentsImportedCount=%v expected=%d", resp["componentsImportedCount"], expected)
}

func TestIngestComponentPublisherMapping(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := IngestHandler(pgStore, IngestConfig{EnqueueWorkers: 1})

	sbomData := loadSBOMFixture(t, "sbom_syft_cyclonedx", "out_cyclonedx_syft_1_6.json")
	req := newMultipartRequest(t, map[string]string{
		"product": "Alpha",
		"scope":   "Payments",
		"test":    "Gateway",
	}, nil, "tags", true, "sbom.json", sbomData)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	rawTestID, _ := resp["testId"].(string)
	testID, err := uuid.Parse(rawTestID)
	if err != nil {
		t.Fatalf("parse testId: %v", err)
	}

	components, err := pgStore.ListComponents(testID)
	if err != nil {
		t.Fatalf("list components: %v", err)
	}

	doc, err := sbom.Parse(sbomData)
	if err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	var expected *sbom.Component
	for i := range doc.Components {
		if doc.Components[i].Properties.Publisher != "" {
			expected = &doc.Components[i]
			break
		}
	}
	if expected == nil {
		t.Fatalf("fixture does not contain publisher data")
	}

	var stored *models.Component
	for i := range components {
		if components[i].PURL == expected.PURL {
			stored = &components[i]
			break
		}
	}
	if stored == nil {
		t.Fatalf("component with purl %s not found", expected.PURL)
	}

	if stored.PkgName != expected.Name {
		t.Fatalf("pkgName mismatch: got %q want %q", stored.PkgName, expected.Name)
	}
	if stored.PkgType != expected.Type {
		t.Fatalf("pkgType mismatch: got %q want %q", stored.PkgType, expected.Type)
	}
	if stored.SbomType != expected.SbomType {
		t.Fatalf("sbomType mismatch: got %q want %q", stored.SbomType, expected.SbomType)
	}
	if stored.Publisher != expected.Properties.Publisher {
		t.Fatalf("publisher mismatch: got %q want %q", stored.Publisher, expected.Properties.Publisher)
	}
}

func TestIngestComponentSupplierMapping(t *testing.T) {
	pgStore, _ := tests.NewPostgresTestStore(t)
	handler := IngestHandler(pgStore, IngestConfig{EnqueueWorkers: 1})

	sbomData := loadSBOMFixture(t, "cdxgen", "cdxgen.json")
	req := newMultipartRequest(t, map[string]string{
		"product": "Beta",
		"scope":   "Core",
		"test":    "Backend",
	}, nil, "tags", true, "sbom.json", sbomData)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, withAuthedRequest(t, pgStore, req))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", recorder.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(recorder.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	rawTestID, _ := resp["testId"].(string)
	testID, err := uuid.Parse(rawTestID)
	if err != nil {
		t.Fatalf("parse testId: %v", err)
	}

	components, err := pgStore.ListComponents(testID)
	if err != nil {
		t.Fatalf("list components: %v", err)
	}

	doc, err := sbom.Parse(sbomData)
	if err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	var expected *sbom.Component
	for i := range doc.Components {
		if doc.Components[i].Properties.Supplier != "" {
			expected = &doc.Components[i]
			break
		}
	}
	if expected == nil {
		t.Fatalf("fixture does not contain supplier data")
	}

	var stored *models.Component
	for i := range components {
		if components[i].PURL == expected.PURL {
			stored = &components[i]
			break
		}
	}
	if stored == nil {
		t.Fatalf("component with purl %s not found", expected.PURL)
	}

	if stored.PkgName != expected.Name {
		t.Fatalf("pkgName mismatch: got %q want %q", stored.PkgName, expected.Name)
	}
	if stored.PkgType != expected.Type {
		t.Fatalf("pkgType mismatch: got %q want %q", stored.PkgType, expected.Type)
	}
	if stored.SbomType != expected.SbomType {
		t.Fatalf("sbomType mismatch: got %q want %q", stored.SbomType, expected.SbomType)
	}
	if stored.Supplier != expected.Properties.Supplier {
		t.Fatalf("supplier mismatch: got %q want %q", stored.Supplier, expected.Properties.Supplier)
	}
}
