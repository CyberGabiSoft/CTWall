package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"backend/internal/core/componentanalysis"
	"backend/internal/store"
)

type componentAnalysisMalwareScheduleResponse struct {
	Enabled   bool      `json:"enabled"`
	Interval  string    `json:"interval"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type componentAnalysisMalwareSchedulePatchRequest struct {
	Enabled  *bool   `json:"enabled"`
	Interval *string `json:"interval"`
}

// GetComponentAnalysisMalwareScheduleHandler returns the current schedule configuration.
func GetComponentAnalysisMalwareScheduleHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.Default().With("component", "handler.component_analysis.schedule.get")
		schedule, err := memStore.GetComponentAnalysisMalwareSchedule()
		if err != nil {
			logger.Error("get schedule failed", "error", err)
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load schedule.", err)
			return
		}
		interval := time.Duration(schedule.IntervalSeconds) * time.Second
		resp := componentAnalysisMalwareScheduleResponse{
			Enabled:   schedule.Enabled,
			Interval:  interval.String(),
			UpdatedAt: schedule.UpdatedAt,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// UpdateComponentAnalysisMalwareScheduleHandler updates schedule configuration and applies it to the runtime scheduler.
func UpdateComponentAnalysisMalwareScheduleHandler(
	memStore store.Store,
	svc *componentanalysis.Service,
	scheduler *componentanalysis.Scheduler,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.Default().With("component", "handler.component_analysis.schedule.patch")

		var payload componentAnalysisMalwareSchedulePatchRequest
		if err := decodeJSON(r, &payload); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON payload.", err)
			return
		}
		if payload.Enabled == nil && payload.Interval == nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "At least one of 'enabled' or 'interval' must be provided.", nil)
			return
		}

		current, err := memStore.GetComponentAnalysisMalwareSchedule()
		if err != nil {
			logger.Error("get schedule failed", "error", err)
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load schedule.", err)
			return
		}

		nextEnabled := current.Enabled
		if payload.Enabled != nil {
			nextEnabled = *payload.Enabled
		}

		nextIntervalSeconds := current.IntervalSeconds
		if payload.Interval != nil {
			raw := strings.TrimSpace(*payload.Interval)
			if raw == "" {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'interval' must not be empty.", nil)
				return
			}
			dur, err := time.ParseDuration(raw)
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'interval' must be a valid duration string (e.g. '24h', '30m').", err)
				return
			}
			if dur < 0 {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'interval' must be >= 0.", nil)
				return
			}
			// Hard bounds: prevent accidental extremely frequent or effectively infinite schedules.
			if dur > 365*24*time.Hour {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'interval' must be <= 8760h (365 days).", nil)
				return
			}
			if dur > 0 && dur < 5*time.Minute {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Field 'interval' must be at least 5m.", nil)
				return
			}
			nextIntervalSeconds = int(dur.Seconds())
		}

		if nextEnabled && nextIntervalSeconds <= 0 {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "When 'enabled' is true, 'interval' must be > 0.", nil)
			return
		}

		updated, err := memStore.UpdateComponentAnalysisMalwareSchedule(nextEnabled, nextIntervalSeconds)
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid schedule configuration.", err)
				return
			}
			logger.Error("update schedule failed", "error", err)
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to update schedule.", err)
			return
		}

		if svc != nil {
			svc.SetSchedule(updated.Enabled, time.Duration(updated.IntervalSeconds)*time.Second)
			svc.SetScheduleAnchor(updated.UpdatedAt)
		}
		if scheduler != nil {
			scheduler.Notify()
		}

		resp := componentAnalysisMalwareScheduleResponse{
			Enabled:   updated.Enabled,
			Interval:  (time.Duration(updated.IntervalSeconds) * time.Second).String(),
			UpdatedAt: updated.UpdatedAt,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
