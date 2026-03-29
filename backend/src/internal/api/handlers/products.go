package handlers

import (
	"log/slog"
	"net/http"
	"strings"

	"backend/internal/store"

	"github.com/google/uuid"
)

type productRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	OwnerGroupID string `json:"ownerGroupId"`
}

// ListProductsHandler returns a paginated list of products.
func ListProductsHandler(memStore store.Store) http.HandlerFunc {
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

		products, err := memStore.ListProductsByProject(project.ID)
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list products.", err)
			return
		}
		writeJSON(w, http.StatusOK, paginate(products, page, pageSize))
	}
}

// CreateProductHandler creates a product.
func CreateProductHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProjectWithRole(r, memStore, store.ProjectRoleWriter)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		var req productRequest
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

		var ownerGroupID *uuid.UUID
		if raw := strings.TrimSpace(req.OwnerGroupID); raw != "" {
			parsed, err := uuid.Parse(raw)
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid ownerGroupId.", err)
				return
			}
			ownerGroupID = &parsed
		}

		product, err := memStore.CreateProductWithOwnerGroup(project.ID, req.Name, req.Description, ownerGroupID, userCtx.ID)
		if err == store.ErrAlreadyExists {
			writeProblem(w, r, http.StatusConflict, "Conflict", "Product already exists.", nil)
			return
		}
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Owner group not found.", nil)
			return
		}
		if err == store.ErrForbidden {
			writeProblem(w, r, http.StatusForbidden, "Forbidden", "Only group OWNER can use the selected owner group.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to create product.", err)
			return
		}

		slog.Debug("product created", "component", "handler.products.create", "product_id", product.ID, "name", product.Name)
		writeJSON(w, http.StatusCreated, product)
	}
}

// GetProductHandler returns a product by ID.
func GetProductHandler(memStore store.Store) http.HandlerFunc {
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

		product, err := memStore.GetProductInProject(project.ID, productID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product.", err)
			return
		}

		writeJSON(w, http.StatusOK, product)
	}
}

// DeleteProductHandler deletes a product.
func DeleteProductHandler(memStore store.Store) http.HandlerFunc {
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

		if err := memStore.DeleteProduct(productID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Product not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete product.", err)
			return
		}

		slog.Debug("product deleted", "component", "handler.products.delete", "product_id", productID)
		w.WriteHeader(http.StatusNoContent)
	}
}
