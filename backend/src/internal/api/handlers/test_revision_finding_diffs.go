package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/store"

	"github.com/google/uuid"
)

// ListTestRevisionLastChangesHandler returns revision-level SBOM delta summaries for a test.
func ListTestRevisionLastChangesHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleReader)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		testID, err := parsePathUUID(r.PathValue("testId"))
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

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		items, err := memStore.ListTestRevisionLastChanges(testID)
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load revision changes.", err)
			return
		}
		writeJSON(w, http.StatusOK, paginate(items, page, pageSize))
	}
}

// GetTestRevisionChangesSummaryHandler returns aggregate counters for one revision diff.
func GetTestRevisionChangesSummaryHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleReader)
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
		if _, err := memStore.GetTestInProject(project.ID, testID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
			return
		}

		item, err := memStore.GetTestRevisionChangeSummary(testID, revisionID)
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision changes not found.", nil)
			return
		}
		if errors.Is(err, store.ErrInvalidPayload) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid identifiers.", err)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load revision change summary.", err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

// ListTestRevisionChangesHandler returns row-level diff entries for one revision.
func ListTestRevisionChangesHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleReader)
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
		if _, err := memStore.GetTestInProject(project.ID, testID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		diffTypes, err := parseDiffTypesQuery(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid diffType filter.", err)
			return
		}

		items, err := memStore.ListTestRevisionFindingDiffs(testID, revisionID, diffTypes)
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision changes not found.", nil)
			return
		}
		if errors.Is(err, store.ErrInvalidPayload) {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid request.", err)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load revision changes.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(items, page, pageSize))
	}
}

func parsePathUUID(raw string) (uuid.UUID, error) {
	return uuid.Parse(strings.TrimSpace(raw))
}

func parseDiffTypesQuery(r *http.Request) ([]string, error) {
	if r == nil || r.URL == nil {
		return []string{}, nil
	}
	values := r.URL.Query()["diffType"]
	if len(values) == 0 {
		raw := strings.TrimSpace(r.URL.Query().Get("diffTypes"))
		if raw == "" {
			return []string{}, nil
		}
		values = strings.Split(raw, ",")
	}

	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.ToUpper(strings.TrimSpace(raw))
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out, nil
}
