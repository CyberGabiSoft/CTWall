package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"backend/internal/store"

	"github.com/google/uuid"
)

const dashboardDefaultRange = "7d"

var dashboardRangePresets = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
}

type dashboardOverviewResponse struct {
	Scope     string                   `json:"scope"`
	ProjectID string                   `json:"projectId"`
	Range     string                   `json:"range"`
	Data      *store.DashboardOverview `json:"data"`
}

// DashboardOverviewHandler returns project-scoped dashboard aggregates.
func DashboardOverviewHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rangeKey, rangeDuration, err := parseDashboardRange(r.URL.Query().Get("range"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid range. Allowed: 24h, 7d, 30d, 90d.", err)
			return
		}
		topN, err := parseDashboardTopN(r.URL.Query().Get("topN"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid topN. Value must be >= 1 or ALL.", err)
			return
		}

		now := time.Now().UTC()
		overview, overviewErr := st.GetDashboardOverview(store.DashboardOverviewQuery{
			ProjectIDs: []uuid.UUID{project.ID},
			Since:      now.Add(-rangeDuration),
			TopN:       topN,
		})
		if overviewErr != nil {
			if errors.Is(overviewErr, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid dashboard query.", overviewErr)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load dashboard overview.", overviewErr)
			return
		}

		writeJSON(w, http.StatusOK, dashboardOverviewResponse{
			Scope:     "project",
			ProjectID: project.ID.String(),
			Range:     rangeKey,
			Data:      overview,
		})
	}
}

func parseDashboardRange(raw string) (string, time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		value = dashboardDefaultRange
	}
	duration, ok := dashboardRangePresets[value]
	if !ok {
		return "", 0, store.ErrInvalidPayload
	}
	return value, duration, nil
}

func parseDashboardTopN(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return store.DefaultDashboardTopN, nil
	}
	if strings.EqualFold(value, "all") {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if parsed == 0 {
		return 0, nil
	}
	if parsed < 0 {
		return 0, store.ErrInvalidPayload
	}
	return parsed, nil
}
