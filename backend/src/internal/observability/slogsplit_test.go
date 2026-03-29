package observability

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestSplitHandlerRoutesBySeverity(t *testing.T) {
	var lowBuf bytes.Buffer
	var highBuf bytes.Buffer

	low := slog.NewTextHandler(&lowBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	high := slog.NewTextHandler(&highBuf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(NewSplitHandler(low, high))

	logger.Debug("debug-low")
	logger.Info("info-low")
	logger.Error("error-high")

	lowOut := lowBuf.String()
	highOut := highBuf.String()
	if !strings.Contains(lowOut, "debug-low") || !strings.Contains(lowOut, "info-low") {
		t.Fatalf("low handler should contain debug/info logs, got: %s", lowOut)
	}
	if strings.Contains(lowOut, "error-high") {
		t.Fatalf("low handler should not contain error logs, got: %s", lowOut)
	}
	if !strings.Contains(highOut, "error-high") {
		t.Fatalf("high handler should contain error logs, got: %s", highOut)
	}
	if strings.Contains(highOut, "info-low") || strings.Contains(highOut, "debug-low") {
		t.Fatalf("high handler should not contain info/debug logs, got: %s", highOut)
	}
}

func TestSplitHandlerNilFallbacks(t *testing.T) {
	base := slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo})
	if handler := NewSplitHandler(nil, base); handler == nil {
		t.Fatalf("expected non-nil split handler when low is nil")
	}
	if handler := NewSplitHandler(base, nil); handler == nil {
		t.Fatalf("expected non-nil split handler when high is nil")
	}
	if handler := NewSplitHandler(nil, nil); handler == nil {
		t.Fatalf("expected non-nil split handler when both handlers are nil")
	}
}
