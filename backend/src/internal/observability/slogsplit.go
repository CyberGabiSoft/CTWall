package observability

import (
	"context"
	"log/slog"
	"os"
)

// SplitHandler routes INFO/WARN/DEBUG logs to one handler and ERROR+ logs to another.
//
// This is used to follow DOCS/best_practices/observability_standards.md:
// - STDOUT for Info/Debug
// - STDERR for Error/Panic
type SplitHandler struct {
	low  slog.Handler
	high slog.Handler
}

func NewSplitHandler(low, high slog.Handler) *SplitHandler {
	switch {
	case low == nil && high == nil:
		fallback := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{})
		low, high = fallback, fallback
	case low == nil:
		low = high
	case high == nil:
		high = low
	}
	return &SplitHandler{low: low, high: high}
}

func (h *SplitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// Both handlers should use the same HandlerOptions.Level, so checking either is fine.
	return h.low.Enabled(ctx, level)
}

func (h *SplitHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		return h.high.Handle(ctx, r)
	}
	return h.low.Handle(ctx, r)
}

func (h *SplitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SplitHandler{
		low:  h.low.WithAttrs(attrs),
		high: h.high.WithAttrs(attrs),
	}
}

func (h *SplitHandler) WithGroup(name string) slog.Handler {
	return &SplitHandler{
		low:  h.low.WithGroup(name),
		high: h.high.WithGroup(name),
	}
}
