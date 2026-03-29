package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"backend/internal/eventmeta"
	"backend/internal/store"
)

const postureDefaultBucket = "day"

type securityPostureOverviewResponse struct {
	Scope     string                         `json:"scope"`
	ProjectID string                         `json:"projectId"`
	Range     string                         `json:"range"`
	Bucket    string                         `json:"bucket"`
	Data      *store.SecurityPostureOverview `json:"data"`
}

// SecurityPostureOverviewHandler returns project-scoped technical posture aggregates.
func SecurityPostureOverviewHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
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
		bucket, err := parsePostureBucket(r.URL.Query().Get("bucket"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid bucket. Allowed: day, week.", err)
			return
		}

		now := time.Now().UTC()
		overview, overviewErr := st.GetSecurityPostureOverview(store.SecurityPostureOverviewQuery{
			ProjectID: project.ID,
			Since:     now.Add(-rangeDuration),
			TopN:      topN,
			Bucket:    bucket,
		})
		if overviewErr != nil {
			if errors.Is(overviewErr, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid posture query.", overviewErr)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load security posture overview.", overviewErr)
			return
		}

		eventsQuery, err := buildEventsQueryFromRequest(r, userCtx, project.ID.String())
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid event filters.", err)
			return
		}
		eventsQuery.Severities = []eventmeta.Severity{eventmeta.SeverityError}
		eventsQuery.CategoriesError = nil
		eventsQuery.CategoriesWarn = nil
		eventsQuery.CategoriesInfo = nil
		eventsQuery.Status = store.EventsStatusOpen
		eventsQuery.From = overview.RangeStart
		eventsQuery.To = overview.RangeEnd

		openErrors, countErr := st.CountOpenEvents(eventsQuery)
		if countErr != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load open events count.", countErr)
			return
		}
		overview.KPIs.OpenErrorEvents = openErrors
		store.ApplySecurityPostureScore(overview)

		writeJSON(w, http.StatusOK, securityPostureOverviewResponse{
			Scope:     "project",
			ProjectID: project.ID.String(),
			Range:     rangeKey,
			Bucket:    bucket,
			Data:      overview,
		})
	}
}

func parsePostureBucket(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		value = postureDefaultBucket
	}
	switch value {
	case "day", "week":
		return value, nil
	default:
		return "", store.ErrInvalidPayload
	}
}
