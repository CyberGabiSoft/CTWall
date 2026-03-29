package handlers

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/config"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type settingsGeneralResponse struct {
	ReadOnly    bool              `json:"readOnly"`
	ConfigPath  string            `json:"configPath"`
	GeneratedAt time.Time         `json:"generatedAt"`
	Config      config.Config     `json:"config"`
	Sources     map[string]string `json:"sources"`
}

// AdminSettingsGeneralHandler returns read-only effective runtime config for Settings > General.
func AdminSettingsGeneralHandler(cfg config.Config, configPath string, sources map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := settingsGeneralResponse{
			ReadOnly:    true,
			ConfigPath:  strings.TrimSpace(configPath),
			GeneratedAt: time.Now().UTC(),
			Config:      cfg,
			Sources:     cloneSettingsSources(sources),
		}

		if auditWriter := middleware.AuditWriterFromContext(r.Context()); auditWriter != nil {
			actorID := resolveActorID(r)
			traceID := middleware.TraceIDFromContext(r.Context())
			component := middleware.ComponentFromContext(r.Context())

			details, err := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryConfig,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleAdmin,
				EventKey:  "config.settings_read",
				TraceID:   traceID,
				Title:     "Settings read",
				Message:   "Admin viewed effective runtime settings.",
				Component: component,
			}, map[string]any{
				"configPath": response.ConfigPath,
				"keys":       sortedKeys(response.Sources),
			})
			if err == nil {
				entry := store.AuditLogEntry{
					ActorID:    actorID,
					Action:     "SETTINGS_READ",
					EntityType: "SETTINGS",
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}
				auditWriter.Write(entry, true)
			}
		}

		writeJSON(w, http.StatusOK, response)
	}
}

func cloneSettingsSources(sources map[string]string) map[string]string {
	if len(sources) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(sources))
	for key, value := range sources {
		k := strings.TrimSpace(key)
		if k == "" {
			continue
		}
		source := strings.TrimSpace(value)
		if source == "" {
			source = "file"
		}
		cloned[k] = source
	}
	return cloned
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func resolveActorID(r *http.Request) *uuid.UUID {
	if r == nil {
		return nil
	}
	userCtx, ok := auth.UserFromContext(r.Context())
	if !ok || userCtx.ID == (uuid.UUID{}) {
		return nil
	}
	id := userCtx.ID
	return &id
}
