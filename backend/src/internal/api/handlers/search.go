package handlers

import (
	"net/http"
	"strings"

	"backend/internal/models"
	"backend/internal/store"
)

// SearchHandler returns products, scopes, and tests matching the query.
func SearchHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		query, err := validateSearchQuery(r.URL.Query().Get("q"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}

		products, err := memStore.ListProductsByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list products.", err)
			return
		}
		scopes, err := memStore.ListAllScopesByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list scopes.", err)
			return
		}
		tests, err := memStore.ListAllTestsByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list tests.", err)
			return
		}

		result := map[string]any{
			"products": filterProducts(products, query),
			"scopes":   filterScopes(scopes, query),
			"tests":    mapTestsResponse(filterTests(tests, query)),
		}

		writeJSON(w, http.StatusOK, result)
	}
}

func filterProducts(items []models.Product, query string) []models.Product {
	filtered := make([]models.Product, 0)
	for _, item := range items {
		if matchesQuery(item.Name, query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterScopes(items []models.Scope, query string) []models.Scope {
	filtered := make([]models.Scope, 0)
	for _, item := range items {
		if matchesQuery(item.Name, query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterTests(items []models.Test, query string) []models.Test {
	filtered := make([]models.Test, 0)
	for _, item := range items {
		if matchesQuery(item.Name, query) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func matchesQuery(value, query string) bool {
	value = strings.ToLower(value)
	query = strings.ToLower(query)

	if strings.Contains(query, "*") {
		parts := strings.Split(query, "*")
		current := 0
		for _, part := range parts {
			if part == "" {
				continue
			}
			index := strings.Index(value[current:], part)
			if index == -1 {
				return false
			}
			current += index + len(part)
		}
		return true
	}

	return strings.Contains(value, query)
}
