package handlers

import (
	"net/http"

	"backend/internal/models"
	"backend/internal/store"
)

func ensureScope(memStore store.Store, product *models.Product, name string) (*models.Scope, *resolveError) {
	if name == "" {
		return nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Field 'scope' or 'scopeId' is required.",
		}
	}
	scope, _, err := memStore.EnsureScope(product.ID, name, "")
	if err == store.ErrNotFound {
		return nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Product not found.",
			err:    err,
		}
	}
	if err != nil {
		return nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve scope.",
			err:    err,
		}
	}
	return scope, nil
}

func ensureTest(memStore store.Store, scope *models.Scope, name string, sbomStandard, sbomSpecVersion string) (*models.Test, *resolveError) {
	if name == "" {
		return nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Field 'test' or 'testId' is required.",
		}
	}
	if sbomStandard == "" || sbomSpecVersion == "" {
		return nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "SBOM standard/spec version must be resolved before creating a test.",
		}
	}
	test, _, err := memStore.EnsureTest(scope.ID, name, sbomStandard, sbomSpecVersion)
	if err == store.ErrNotFound {
		return nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Scope not found.",
			err:    err,
		}
	}
	if err != nil {
		return nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve test.",
			err:    err,
		}
	}
	return test, nil
}
