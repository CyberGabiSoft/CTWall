package handlers

import (
	"net/http"

	"backend/internal/store"

	"github.com/google/uuid"
)

type componentCountResponse struct {
	Count int `json:"count"`
}

// CountComponentsHandler returns the total component count for the active revision of a test.
func CountComponentsHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("testId")
		testID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid testId.", err)
			return
		}
		if _, err := memStore.GetTestInProject(project.ID, testID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
			return
		}

		count, err := memStore.CountComponents(testID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to count components.", err)
			return
		}

		writeJSON(w, http.StatusOK, componentCountResponse{Count: count})
	}
}
