package handlers

import (
	"net/http"
	"time"
	"unicode/utf8"

	"backend/internal/store"

	"github.com/google/uuid"
)

type componentOccurrencesResponse struct {
	Items []componentOccurrenceItem `json:"items"`
	Total int                       `json:"total"`
}

type componentOccurrenceItem struct {
	ComponentID          uuid.UUID  `json:"componentId"`
	RevisionID           uuid.UUID  `json:"revisionId"`
	PURL                 string     `json:"purl"`
	PkgName              string     `json:"pkgName"`
	Version              string     `json:"version"`
	PkgType              string     `json:"pkgType"`
	PkgNamespace         string     `json:"pkgNamespace,omitempty"`
	TestID               uuid.UUID  `json:"testId"`
	TestName             string     `json:"testName"`
	ScopeID              uuid.UUID  `json:"scopeId"`
	ScopeName            string     `json:"scopeName"`
	ProductID            uuid.UUID  `json:"productId"`
	ProductName          string     `json:"productName"`
	CreatedAt            time.Time  `json:"createdAt"`
	MalwareVerdict       string     `json:"malwareVerdict"`
	MalwareFindingsCount int        `json:"malwareFindingsCount"`
	MalwareScannedAt     *time.Time `json:"malwareScannedAt,omitempty"`
	MalwareValidUntil    *time.Time `json:"malwareValidUntil,omitempty"`
}

// SearchComponentOccurrencesHandler lists component occurrences across all active test revisions.
func SearchComponentOccurrencesHandler(memStore store.Store) http.HandlerFunc {
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

		q, err := validateSearchQuery(r.URL.Query().Get("q"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		if utf8.RuneCountInString(q) < 2 {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Query parameter 'q' must be at least 2 characters.", nil)
			return
		}

		offset := (page - 1) * pageSize
		results, total, err := memStore.SearchComponentOccurrencesPageByProject(project.ID, q, pageSize, offset)
		if err != nil {
			if err == store.ErrInvalidPayload {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid query parameters.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to search component occurrences.", err)
			return
		}

		items := make([]componentOccurrenceItem, 0, len(results))
		for _, occ := range results {
			item := componentOccurrenceItem{
				ComponentID:          occ.ComponentID,
				RevisionID:           occ.RevisionID,
				PURL:                 occ.PURL,
				PkgName:              occ.PkgName,
				Version:              occ.Version,
				PkgType:              occ.PkgType,
				PkgNamespace:         occ.PkgNamespace,
				TestID:               occ.TestID,
				TestName:             occ.TestName,
				ScopeID:              occ.ScopeID,
				ScopeName:            occ.ScopeName,
				ProductID:            occ.ProductID,
				ProductName:          occ.ProductName,
				CreatedAt:            occ.CreatedAt.UTC(),
				MalwareVerdict:       occ.MalwareVerdict,
				MalwareFindingsCount: occ.MalwareFindingsCount,
			}
			item.MalwareScannedAt = occ.MalwareScannedAt
			item.MalwareValidUntil = occ.MalwareValidUntil
			items = append(items, item)
		}

		writeJSON(w, http.StatusOK, componentOccurrencesResponse{Items: items, Total: total})
	}
}
