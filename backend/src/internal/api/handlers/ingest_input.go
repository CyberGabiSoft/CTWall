package handlers

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func parseIngestInput(r *http.Request) (ingestInput, *resolveError) {
	input := ingestInput{
		productName: strings.TrimSpace(r.FormValue("product")),
		scopeName:   strings.TrimSpace(r.FormValue("scope")),
		testName:    strings.TrimSpace(r.FormValue("test")),
	}

	testIDRaw := strings.TrimSpace(r.FormValue("testId"))
	if testIDRaw != "" {
		testID, err := uuid.Parse(testIDRaw)
		if err != nil {
			return ingestInput{}, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Field 'testId' must be a valid UUID.",
				err:    err,
			}
		}
		input.testID = &testID
		return input, nil
	}

	scopeIDRaw := strings.TrimSpace(r.FormValue("scopeId"))
	if scopeIDRaw != "" {
		scopeID, err := uuid.Parse(scopeIDRaw)
		if err != nil {
			return ingestInput{}, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Field 'scopeId' must be a valid UUID.",
				err:    err,
			}
		}
		input.scopeID = &scopeID

		productIDRaw := strings.TrimSpace(r.FormValue("productId"))
		if productIDRaw != "" {
			productID, err := uuid.Parse(productIDRaw)
			if err == nil {
				input.productID = &productID
			}
		}
		return input, nil
	}

	productIDRaw := strings.TrimSpace(r.FormValue("productId"))
	if productIDRaw != "" {
		productID, err := uuid.Parse(productIDRaw)
		if err != nil {
			return ingestInput{}, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: "Field 'productId' must be a valid UUID.",
				err:    err,
			}
		}
		input.productID = &productID
	}

	return input, nil
}
