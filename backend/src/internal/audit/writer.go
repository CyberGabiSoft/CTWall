package audit

import (
	"log/slog"
	"strings"

	"backend/internal/store"
)

// Config controls where audit logs are stored.
type Config struct {
	StoreAllLogs          bool
	StoreConfidentialLogs bool
}

// Writer writes audit entries to the configured sink(s).
type Writer struct {
	store  store.Store
	cfg    Config
	logger *slog.Logger
}

// NewWriter creates a new audit writer.
func NewWriter(st store.Store, cfg Config, logger *slog.Logger) *Writer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Writer{
		store:  st,
		cfg:    cfg,
		logger: logger.With("component", "audit.writer"),
	}
}

// ShouldStore reports whether an audit entry should be persisted in the database.
func (c Config) ShouldStore(confidential bool, mustStore bool) bool {
	if mustStore {
		return true
	}
	if c.StoreAllLogs {
		return true
	}
	if confidential && c.StoreConfidentialLogs {
		return true
	}
	return false
}

// Write persists the audit log entry if allowed by config.
func (w *Writer) Write(entry store.AuditLogEntry, confidential bool) {
	if w == nil {
		return
	}
	stored := false
	if w.store != nil && w.cfg.ShouldStore(confidential, mustStoreAuditEntry(entry)) {
		if err := w.store.CreateAuditLog(entry); err != nil {
			action := strings.TrimSpace(entry.Action)
			w.logger.Error("audit log write failed", "action", action, "error", err)
		} else {
			stored = true
		}
	}
	if w.logger == nil {
		return
	}
	attributes := []any{
		"event_type", "audit",
		"action", strings.TrimSpace(entry.Action),
		"entity_type", strings.TrimSpace(entry.EntityType),
		"stored", stored,
		"confidential", confidential,
	}
	if entry.ActorID != nil {
		attributes = append(attributes, "actor_id", entry.ActorID)
	}
	if entry.EntityID != nil {
		attributes = append(attributes, "entity_id", entry.EntityID)
	}
	if entry.IPAddress != "" {
		attributes = append(attributes, "ip", SanitizeIPAddress(entry.IPAddress))
	}
	if len(entry.Details) > 0 {
		attributes = append(attributes, "details", SanitizeLogValue(string(entry.Details)))
	}
	w.logger.Info("audit event", attributes...)
}

func mustStoreAuditEntry(entry store.AuditLogEntry) bool {
	action := strings.TrimSpace(entry.Action)
	if action == "" {
		return false
	}

	// Must-have audit trail entries and UI-backed histories.
	switch {
	case strings.HasPrefix(action, "LOGIN_"),
		strings.HasPrefix(action, "LOGOUT_"),
		strings.HasPrefix(action, "PASSWORD_CHANGE_"),
		strings.HasPrefix(action, "PROJECT_"),
		strings.HasPrefix(action, "USER_"),
		strings.HasPrefix(action, "TOKEN_"),
		strings.HasPrefix(action, "MALWARE_OSV_SYNC_"),
		strings.HasPrefix(action, "MALWARE_FINDING_"),
		strings.HasPrefix(action, "MALWARE_SOURCE_RESULTS_RECOMPUTE_"),
		action == "AUTHZ_DENY",
		action == "AUTHN_DENY",
		action == "API_ERROR_5XX",
		action == "EVENT_ACK":
		return true
	default:
		return false
	}
}
