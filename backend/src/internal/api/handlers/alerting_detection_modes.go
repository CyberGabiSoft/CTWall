package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"
)

type alertDetectionModesResponse struct {
	Items []models.AlertDetectionMode `json:"items"`
}

type alertDetectionModePayload struct {
	Mode         string `json:"mode"`
	Enabled      *bool  `json:"enabled,omitempty"`
	Severity     string `json:"severity"`
	LookbackDays *int   `json:"lookbackDays,omitempty"`
}

type putAlertDetectionModesRequest struct {
	Modes []alertDetectionModePayload `json:"modes"`
}

func ListAlertDetectionModesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		items, err := st.ListAlertDetectionModes(project.ID)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid detection mode query.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load alert detection modes.", err)
			return
		}
		writeJSON(w, http.StatusOK, alertDetectionModesResponse{Items: items})
	}
}

func PutAlertDetectionModesHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, st, store.ProjectRoleWriter)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		var req putAlertDetectionModesRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		if len(req.Modes) == 0 {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "modes is required.", nil)
			return
		}

		inputs := make([]store.AlertDetectionModeInput, 0, len(req.Modes))
		for _, raw := range req.Modes {
			mode := strings.ToUpper(strings.TrimSpace(raw.Mode))
			var normalizedMode store.AlertDetectionMode
			switch mode {
			case string(store.AlertDetectionModePURLVersionSmart):
				normalizedMode = store.AlertDetectionModePURLVersionSmart
			case string(store.AlertDetectionModePURLContainsPrefix):
				normalizedMode = store.AlertDetectionModePURLContainsPrefix
			default:
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid detection mode.", nil)
				return
			}

			severity := strings.ToUpper(strings.TrimSpace(raw.Severity))
			if severity == "WARNING" {
				severity = "WARN"
			}
			if !eventmeta.ValidSeverity(severity) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid detection mode severity.", nil)
				return
			}

			enabled := false
			if raw.Enabled != nil {
				enabled = *raw.Enabled
			}
			var lookbackDays *int
			if normalizedMode == store.AlertDetectionModePURLContainsPrefix {
				if raw.LookbackDays != nil {
					if *raw.LookbackDays <= 0 {
						writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid lookbackDays for detection mode.", nil)
						return
					}
					value := *raw.LookbackDays
					lookbackDays = &value
				}
			}

			inputs = append(inputs, store.AlertDetectionModeInput{
				Mode:         normalizedMode,
				Enabled:      enabled,
				Severity:     eventmeta.Severity(severity),
				LookbackDays: lookbackDays,
			})
		}

		items, err := st.ReplaceAlertDetectionModes(project.ID, inputs)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid detection modes payload.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save detection modes.", err)
			return
		}
		if _, reconcileErr := st.ReconcileMalwareAlertGroupsForProject(project.ID, &userCtx.ID); reconcileErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to reconcile malware alerts after detection mode update.", reconcileErr)
			return
		}

		if auditWriter != nil {
			details, derr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryConfig,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleWrite,
				EventKey:  "alerts.detection_modes.update",
				ProjectID: project.ID.String(),
				Title:     "Alert detection modes updated",
				Message:   "User updated malware alert detection modes.",
				Component: "handler.alerting.detection_modes.put",
			}, map[string]any{
				"modesCount": len(items),
			})
			if derr == nil {
				auditWriter.Write(store.AuditLogEntry{
					ActorID:    &userCtx.ID,
					Action:     "ALERT_DETECTION_MODES_UPDATE",
					EntityType: "alert_detection_mode",
					EntityID:   nil,
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}, true)
			}
		}

		writeJSON(w, http.StatusOK, alertDetectionModesResponse{Items: items})
	}
}
