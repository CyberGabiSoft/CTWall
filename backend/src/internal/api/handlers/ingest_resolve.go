package handlers

import (
	"net/http"
	"strings"

	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

func resolveEntitiesInputForProject(input ingestInput, projectID uuid.UUID, memStore store.Store) (*models.Product, *models.Scope, *models.Test, *resolveError) {
	isProjectScoped := projectID != uuid.Nil
	productName := input.productName
	scopeName := input.scopeName
	testName := input.testName

	if input.testID != nil {
		test, resolveErr := loadTest(memStore, isProjectScoped, projectID, *input.testID)
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		scope, resolveErr := loadScope(memStore, isProjectScoped, projectID, test.ScopeID, "Scope not found for test.")
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		product, resolveErr := loadProduct(memStore, isProjectScoped, projectID, scope.ProductID, "Product not found for test.", "Failed to load product for test.")
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}

		if input.sbomStandard != "" && !strings.EqualFold(test.SbomStandard, input.sbomStandard) {
			return nil, nil, nil, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Uploaded SBOM standard does not match the selected test.",
			}
		}
		if input.sbomSpecVersion != "" && !strings.EqualFold(test.SbomSpecVersion, input.sbomSpecVersion) {
			return nil, nil, nil, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Uploaded SBOM spec version does not match the selected test.",
			}
		}
		return product, scope, test, nil
	}

	var product *models.Product
	if input.scopeID != nil {
		scope, resolveErr := loadScope(memStore, isProjectScoped, projectID, *input.scopeID, "Scope not found.")
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		loadedProduct, resolveErr := loadProduct(memStore, isProjectScoped, projectID, scope.ProductID, "Product not found for scope.", "Failed to load product for scope.")
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		product = loadedProduct

		if input.productID != nil {
			if *input.productID != product.ID {
				return nil, nil, nil, &resolveError{
					status: http.StatusBadRequest,
					title:  "Invalid Request",
					detail: "Provided productId does not match scopeId.",
				}
			}
		}
		if productName != "" && !strings.EqualFold(product.Name, productName) {
			return nil, nil, nil, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Provided product name does not match scopeId.",
			}
		}

		test, resolveErr := ensureTest(memStore, scope, testName, input.sbomStandard, input.sbomSpecVersion)
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		return product, scope, test, nil
	}

	if input.productID != nil {
		found, resolveErr := loadProduct(memStore, isProjectScoped, projectID, *input.productID, "Product not found.", "Failed to load product.")
		if resolveErr != nil {
			return nil, nil, nil, resolveErr
		}
		product = found
	} else if productName != "" {
		var (
			created *models.Product
			err     error
		)
		if isProjectScoped {
			created, _, err = memStore.EnsureProductInProject(projectID, productName, "")
		} else {
			created, _, err = memStore.EnsureProduct(productName, "")
		}
		if err != nil {
			return nil, nil, nil, &resolveError{
				status: http.StatusInternalServerError,
				title:  "Internal Error",
				detail: "Failed to resolve product.",
				err:    err,
			}
		}
		product = created
	} else {
		return nil, nil, nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Field 'product' or 'productId' is required.",
		}
	}

	scope, resolveErr := ensureScope(memStore, product, scopeName)
	if resolveErr != nil {
		return nil, nil, nil, resolveErr
	}

	test, resolveErr := ensureTest(memStore, scope, testName, input.sbomStandard, input.sbomSpecVersion)
	if resolveErr != nil {
		return nil, nil, nil, resolveErr
	}

	return product, scope, test, nil
}

func loadTest(memStore store.Store, scoped bool, projectID, testID uuid.UUID) (*models.Test, *resolveError) {
	var (
		test *models.Test
		err  error
	)
	if scoped {
		test, err = memStore.GetTestInProject(projectID, testID)
	} else {
		test, err = memStore.GetTest(testID)
	}
	if err == store.ErrNotFound {
		return nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Test not found.",
		}
	}
	if err != nil {
		return nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load test.",
			err:    err,
		}
	}
	return test, nil
}

func loadScope(memStore store.Store, scoped bool, projectID, scopeID uuid.UUID, notFoundDetail string) (*models.Scope, *resolveError) {
	var (
		scope *models.Scope
		err   error
	)
	if scoped {
		scope, err = memStore.GetScopeInProject(projectID, scopeID)
	} else {
		scope, err = memStore.GetScope(scopeID)
	}
	if err == store.ErrNotFound {
		return nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: notFoundDetail,
		}
	}
	if err != nil {
		return nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load scope.",
			err:    err,
		}
	}
	return scope, nil
}

func loadProduct(memStore store.Store, scoped bool, projectID, productID uuid.UUID, notFoundDetail, loadFailedDetail string) (*models.Product, *resolveError) {
	var (
		product *models.Product
		err     error
	)
	if scoped {
		product, err = memStore.GetProductInProject(projectID, productID)
	} else {
		product, err = memStore.GetProduct(productID)
	}
	if err == store.ErrNotFound {
		return nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: notFoundDetail,
		}
	}
	if err != nil {
		return nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: loadFailedDetail,
			err:    err,
		}
	}
	return product, nil
}
