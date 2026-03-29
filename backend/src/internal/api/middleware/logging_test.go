package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"backend/internal/audit"
)

func TestWithLogging_PropagatesContextAndTraceHeader(t *testing.T) {
	const inputTrace = "ABCDEF0123456789ABCDEF0123456789"
	aw := &audit.Writer{}

	var (
		gotTrace     string
		gotComponent string
		gotPattern   string
		gotWriter    *audit.Writer
	)

	h := WithLogging("router.products", aw, func(w http.ResponseWriter, r *http.Request) {
		gotTrace = TraceIDFromContext(r.Context())
		gotComponent = ComponentFromContext(r.Context())
		gotPattern = RoutePatternFromContext(r.Context())
		gotWriter = AuditWriterFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Pattern = "/api/v1/products"
	req.Header.Set("X-Trace-Id", inputTrace)
	rec := httptest.NewRecorder()

	h(rec, req)

	if gotTrace != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("unexpected trace id in context: %q", gotTrace)
	}
	if got := rec.Header().Get("X-Trace-Id"); got != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("unexpected trace id header: %q", got)
	}
	if gotComponent != "router.products" {
		t.Fatalf("unexpected component: %q", gotComponent)
	}
	if gotPattern != "/api/v1/products" {
		t.Fatalf("unexpected route pattern: %q", gotPattern)
	}
	if gotWriter != aw {
		t.Fatalf("unexpected audit writer pointer")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rec.Code)
	}
}

func TestWithLogging_FallbacksForMissingPatternAndInvalidTrace(t *testing.T) {
	var gotPattern string
	var gotTrace string

	h := WithLogging("router.any", nil, func(w http.ResponseWriter, r *http.Request) {
		gotPattern = RoutePatternFromContext(r.Context())
		gotTrace = TraceIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/fallback", nil)
	req.Header.Set("X-Trace-Id", "not-valid")
	rec := httptest.NewRecorder()

	h(rec, req)

	if gotPattern != "/api/v1/fallback" {
		t.Fatalf("expected URL path fallback pattern, got %q", gotPattern)
	}
	if len(gotTrace) != 32 || !isHexTraceID(gotTrace) {
		t.Fatalf("expected generated 32-char hex trace id, got %q", gotTrace)
	}
}

func TestEnsureTraceIDAndHelpers(t *testing.T) {
	if got := ensureTraceID(nil); len(got) != 32 || !isHexTraceID(got) {
		t.Fatalf("expected generated trace id for nil request, got %q", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req.Header.Set("X-Trace-Id", "123")
	if got := ensureTraceID(req); len(got) != 32 || !isHexTraceID(got) {
		t.Fatalf("expected generated trace id for invalid header, got %q", got)
	}

	if got := newTraceID(); len(got) != 32 || !isHexTraceID(got) {
		t.Fatalf("unexpected newTraceID output: %q", got)
	}

	if !isHexTraceID("abcdef0123456789ABCDEF0123456789") {
		t.Fatalf("expected mixed-case hex trace to be valid")
	}
	if isHexTraceID("g123ef0123456789abcdef0123456789") {
		t.Fatalf("expected non-hex trace to be invalid")
	}
}

func TestContextAccessors_NilAndWrongTypes(t *testing.T) {
	if got := TraceIDFromContext(context.TODO()); got != "" {
		t.Fatalf("expected empty trace for nil context")
	}
	if got := ComponentFromContext(context.TODO()); got != "" {
		t.Fatalf("expected empty component for nil context")
	}
	if got := RoutePatternFromContext(context.TODO()); got != "" {
		t.Fatalf("expected empty pattern for nil context")
	}
	if got := AuditWriterFromContext(context.TODO()); got != nil {
		t.Fatalf("expected nil writer for nil context")
	}

	ctx := context.Background()
	ctx = context.WithValue(ctx, traceIDKey, 123)
	ctx = context.WithValue(ctx, componentKey, 456)
	ctx = context.WithValue(ctx, routePatternKey, 789)
	ctx = context.WithValue(ctx, auditWriterKey, "bad")

	if got := TraceIDFromContext(ctx); got != "" {
		t.Fatalf("expected empty trace for wrong type")
	}
	if got := ComponentFromContext(ctx); got != "" {
		t.Fatalf("expected empty component for wrong type")
	}
	if got := RoutePatternFromContext(ctx); got != "" {
		t.Fatalf("expected empty route pattern for wrong type")
	}
	if got := AuditWriterFromContext(ctx); got != nil {
		t.Fatalf("expected nil writer for wrong type")
	}
}
