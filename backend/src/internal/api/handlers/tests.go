package handlers

import (
	"log/slog"
	"net/http"

	"backend/internal/store"

	"github.com/google/uuid"
)

// ListAllTestsHandler returns a paginated list of all tests.
func ListAllTestsHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		tests, err := memStore.ListAllTestsByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list tests.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(mapTestsResponse(tests), page, pageSize))
	}
}

// ListTestsHandler returns a paginated list of tests for a scope.
func ListTestsHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("scopeId")
		scopeID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid scopeId.", err)
			return
		}
		if _, err := memStore.GetScopeInProject(project.ID, scopeID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Scope not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load scope.", err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		tests, err := memStore.ListTests(scopeID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Scope not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list tests.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(mapTestsResponse(tests), page, pageSize))
	}
}

// ListRevisionsHandler returns a paginated list of revisions for a test.
func ListRevisionsHandler(memStore store.Store) http.HandlerFunc {
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

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		revisions, err := memStore.ListRevisions(testID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list revisions.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(revisions, page, pageSize))
	}
}

// DeleteTestHandler deletes a test.
func DeleteTestHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleWriter)
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

		if err := memStore.DeleteTest(testID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete test.", err)
			return
		}

		slog.Debug("test deleted", "component", "handler.tests.delete", "test_id", testID)
		w.WriteHeader(http.StatusNoContent)
	}
}
