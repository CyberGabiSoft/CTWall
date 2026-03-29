package middleware

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"backend/internal/audit"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

type ctxKey int

const (
	traceIDKey ctxKey = iota
	componentKey
	routePatternKey
	auditWriterKey
)

// WithLogging wraps a handler with request context + minimal request logs.
// - Adds/propagates a request-scoped trace id (X-Trace-Id).
// - Stores component + route pattern + audit writer in context for downstream handlers.
// - Emits a stable INFO request-end log for "major step" observability.
func WithLogging(component string, auditWriter *audit.Writer, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		traceID := ensureTraceID(r)
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" {
			pattern = strings.TrimSpace(r.URL.Path)
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, traceIDKey, traceID)
		ctx = context.WithValue(ctx, componentKey, strings.TrimSpace(component))
		ctx = context.WithValue(ctx, routePatternKey, pattern)
		ctx = context.WithValue(ctx, auditWriterKey, auditWriter)
		r = r.WithContext(ctx)

		if traceID != "" {
			w.Header().Set("X-Trace-Id", traceID)
		}

		slog.Debug("request start",
			"component", strings.TrimSpace(component),
			"trace_id", traceID,
			"method", r.Method,
			"pattern", pattern,
		)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		slog.Info("request end",
			"component", strings.TrimSpace(component),
			"trace_id", traceID,
			"method", r.Method,
			"pattern", pattern,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}
}

func ensureTraceID(r *http.Request) string {
	if r == nil {
		return newTraceID()
	}
	// Prefer caller-provided trace id if it looks sane (32 hex chars).
	if candidate := strings.TrimSpace(r.Header.Get("X-Trace-Id")); isHexTraceID(candidate) {
		return strings.ToLower(candidate)
	}
	return newTraceID()
}

func newTraceID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback: time-based 16 bytes (still better than empty).
		binary.LittleEndian.PutUint64(buf[:8], uint64(time.Now().UTC().UnixNano()))
		binary.LittleEndian.PutUint64(buf[8:], uint64(time.Now().UTC().UnixNano()>>1))
	}
	return hex.EncodeToString(buf[:])
}

func isHexTraceID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func TraceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(traceIDKey).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func ComponentFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(componentKey).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func RoutePatternFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(routePatternKey).(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func AuditWriterFromContext(ctx context.Context) *audit.Writer {
	if ctx == nil {
		return nil
	}
	if v, ok := ctx.Value(auditWriterKey).(*audit.Writer); ok {
		return v
	}
	return nil
}
