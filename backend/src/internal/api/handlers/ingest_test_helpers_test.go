package handlers

import (
	"net/http"

	"backend/internal/models"
	"backend/internal/store"

	"backend/internal/sbom"

	"github.com/google/uuid"
)

func resolveEntities(r *http.Request, memStore store.Store) (*models.Product, *models.Scope, *models.Test, *resolveError) {
	input, resolveErr := parseIngestInput(r)
	if resolveErr != nil {
		return nil, nil, nil, resolveErr
	}
	if input.sbomStandard == "" && input.sbomSpecVersion == "" {
		if parsedType, provided, err := parseSbomTypeField(r.FormValue("sbomType")); err != nil {
			return nil, nil, nil, &resolveError{
				status: http.StatusBadRequest,
				title:  "Invalid Request",
				detail: err.Error(),
				err:    err,
			}
		} else if provided {
			input.sbomStandard = string(parsedType.Standard)
			input.sbomSpecVersion = parsedType.SpecVersion
		}
	}
	return resolveEntitiesInput(input, memStore)
}

func resolveEntitiesInput(input ingestInput, memStore store.Store) (*models.Product, *models.Scope, *models.Test, *resolveError) {
	return resolveEntitiesInputForProject(input, uuid.Nil, memStore)
}

func countComponents(data []byte, isGzip bool) int {
	doc, err := sbom.ParseMaybeGzip(data, isGzip)
	if err != nil || doc == nil {
		return 0
	}
	return len(doc.Components)
}
