package handlers

import (
	"log/slog"
	"net/http"

	"backend/internal/store"

	"github.com/google/uuid"
)

type scopeRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ListAllScopesHandler returns a paginated list of all scopes.
func ListAllScopesHandler(memStore store.Store) http.HandlerFunc {
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

		scopes, err := memStore.ListAllScopesByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list scopes.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(scopes, page, pageSize))
	}
}

// ListScopesHandler returns a paginated list of scopes for a product.
func ListScopesHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("productId")
		productID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productId.", err)
			return
		}
		if _, err := memStore.GetProductInProject(project.ID, productID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product.", err)
			return
		}

		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid pagination parameters.", err)
			return
		}

		scopes, err := memStore.ListScopes(productID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list scopes.", err)
			return
		}

		writeJSON(w, http.StatusOK, paginate(scopes, page, pageSize))
	}
}

// CreateScopeHandler creates a scope under a product.
func CreateScopeHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleWriter)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("productId")
		productID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid productId.", err)
			return
		}
		if _, err := memStore.GetProductInProject(project.ID, productID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product.", err)
			return
		}

		var req scopeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}

		name, err := validateName("name", req.Name, true)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), nil)
			return
		}
		req.Name = name
		req.Description = sanitizePlainText(req.Description)

		scope, err := memStore.CreateScope(productID, req.Name, req.Description)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Scope already exists.", nil)
			return
		}
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create scope.", err)
			return
		}

		slog.Debug("scope created", "component", "handler.scopes.create", "scope_id", scope.ID, "product_id", scope.ProductID, "name", scope.Name)
		writeJSON(w, http.StatusCreated, scope)
	}
}

// DeleteScopeHandler deletes a scope.
func DeleteScopeHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleWriter)
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

		if err := memStore.DeleteScope(scopeID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Scope not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete scope.", err)
			return
		}

		slog.Debug("scope deleted", "component", "handler.scopes.delete", "scope_id", scopeID)
		w.WriteHeader(http.StatusNoContent)
	}
}
