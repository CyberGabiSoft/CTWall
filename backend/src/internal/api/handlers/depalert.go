package handlers

import (
	"errors"
	"net/http"
	"time"

	"backend/internal/store"
)

type depAlertRevisionVerdictResponse struct {
	ProjectID         string `json:"projectId"`
	TestID            string `json:"testId"`
	RevisionID        string `json:"revisionId"`
	Verdict           string `json:"verdict"`
	TotalComponents   int    `json:"totalComponents"`
	MalwareComponents int    `json:"malwareComponents"`
	CleanComponents   int    `json:"cleanComponents"`
	UnknownComponents int    `json:"unknownComponents"`
	ComputedAt        string `json:"computedAt"`
}

// GetDepAlertRevisionVerdictHandler returns a project-scoped revision malware verdict for DepAlert.
func GetDepAlertRevisionVerdictHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		testID, err := parsePathUUID(r.PathValue("testId"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId.", err)
			return
		}
		revisionID, err := parsePathUUID(r.PathValue("revisionId"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid revisionId.", err)
			return
		}

		verdict, err := memStore.GetDepAlertRevisionVerdict(project.ID, testID, revisionID)
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision not found in selected project.", nil)
			return
		}
		if errors.Is(err, store.ErrInvalidPayload) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId or revisionId.", err)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load revision verdict.", err)
			return
		}

		writeJSON(w, http.StatusOK, depAlertRevisionVerdictResponse{
			ProjectID:         verdict.ProjectID.String(),
			TestID:            verdict.TestID.String(),
			RevisionID:        verdict.RevisionID.String(),
			Verdict:           verdict.Verdict,
			TotalComponents:   verdict.TotalComponents,
			MalwareComponents: verdict.MalwareComponents,
			CleanComponents:   verdict.CleanComponents,
			UnknownComponents: verdict.UnknownComponents,
			ComputedAt:        verdict.ComputedAt.UTC().Format(time.RFC3339),
		})
	}
}
