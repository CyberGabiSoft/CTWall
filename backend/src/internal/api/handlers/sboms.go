package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"backend/internal/store"

	"backend/internal/sbom"
	"github.com/google/uuid"
)

type sbomListItem struct {
	RevisionID              uuid.UUID       `json:"revisionId"`
	TestID                  uuid.UUID       `json:"testId"`
	ScopeID                 uuid.UUID       `json:"scopeId"`
	ProductID               uuid.UUID       `json:"productId"`
	SbomSha256              string          `json:"sbomSha256"`
	SbomType                sbomTypePayload `json:"sbomType"`
	SbomProducer            string          `json:"sbomProducer"`
	Tags                    []string        `json:"tags"`
	ComponentsImportedCount int             `json:"componentsImportedCount"`
	IsActive                bool            `json:"isActive"`
	LastModifiedAt          time.Time       `json:"lastModifiedAt"`
	CreatedAt               time.Time       `json:"createdAt"`
}

// ListSbomsHandler returns a flat, paginated list of SBOM revisions.
func ListSbomsHandler(memStore store.Store) http.HandlerFunc {
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

		filters, err := parseSbomFilters(r)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}

		revisions, err := memStore.ListAllRevisions()
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list revisions.", err)
			return
		}
		results := make([]sbomListItem, 0, len(revisions))

		for _, revision := range revisions {
			test, err := memStore.GetTestInProject(project.ID, revision.TestID)
			if err == store.ErrNotFound {
				continue
			}
			if err != nil {
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load test.", err)
				return
			}
			scope, err := memStore.GetScope(test.ScopeID)
			if err == store.ErrNotFound {
				continue
			}
			if err != nil {
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load scope.", err)
				return
			}
			product, err := memStore.GetProductInProject(project.ID, scope.ProductID)
			if err == store.ErrNotFound {
				continue
			}
			if err != nil {
				writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load product.", err)
				return
			}

			if filters.productID != nil && *filters.productID != product.ID {
				continue
			}
			if filters.scopeID != nil && *filters.scopeID != scope.ID {
				continue
			}
			if filters.testID != nil && *filters.testID != test.ID {
				continue
			}
			if filters.sbomStandard != "" && !strings.EqualFold(filters.sbomStandard, test.SbomStandard) {
				continue
			}
			if filters.sbomSpecVersion != "" && !strings.EqualFold(filters.sbomSpecVersion, test.SbomSpecVersion) {
				continue
			}
			if filters.sbomProducer != "" && !strings.EqualFold(filters.sbomProducer, revision.SbomProducer) {
				continue
			}
			if filters.tag != "" && !hasTag(revision.Tags, filters.tag) {
				continue
			}

			results = append(results, sbomListItem{
				RevisionID: revision.ID,
				TestID:     test.ID,
				ScopeID:    scope.ID,
				ProductID:  product.ID,
				SbomSha256: revision.SbomSha256,
				SbomType: sbomTypePayload{
					Standard:    test.SbomStandard,
					SpecVersion: test.SbomSpecVersion,
				},
				SbomProducer:            revision.SbomProducer,
				Tags:                    revision.Tags,
				ComponentsImportedCount: revision.ComponentsImportedCount,
				IsActive:                revision.IsActive,
				LastModifiedAt:          revision.LastModifiedAt,
				CreatedAt:               revision.CreatedAt,
			})
		}

		sort.Slice(results, func(i, j int) bool {
			return results[i].CreatedAt.After(results[j].CreatedAt)
		})

		writeJSON(w, http.StatusOK, paginate(results, page, pageSize))
	}
}

// DownloadSbomHandler streams the original SBOM payload for a revision.
func DownloadSbomHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("revisionId")
		revisionID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid revisionId.", err)
			return
		}

		revision, err := memStore.GetRevisionInProject(project.ID, revisionID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load revision.", err)
			return
		}

		sbom, err := memStore.GetSbomBySHA(revision.SbomSha256)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "SBOM data not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load SBOM data.", err)
			return
		}

		filename := "sbom-" + revision.ID.String() + ".json"
		contentType := strings.TrimSpace(sbom.ContentType)
		if sbom.IsGzip {
			contentType = "application/gzip"
			filename = "sbom-" + revision.ID.String() + ".gz"
		}
		if contentType == "" {
			contentType = "application/json"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sbom.Bytes)
	}
}

// DeleteSbomHandler deletes a revision and its SBOM data if orphaned.
func DeleteSbomHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawID := r.PathValue("revisionId")
		revisionID, err := uuid.Parse(rawID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid revisionId.", err)
			return
		}

		if err := memStore.DeleteRevisionInProject(project.ID, revisionID); err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Revision not found.", nil)
			return
		} else if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to delete revision.", err)
			return
		}

		slog.Debug("sbom revision deleted", "component", "handler.sboms.delete", "revision_id", revisionID)
		w.WriteHeader(http.StatusNoContent)
	}
}

type sbomFilters struct {
	productID       *uuid.UUID
	scopeID         *uuid.UUID
	testID          *uuid.UUID
	sbomStandard    string
	sbomSpecVersion string
	sbomProducer    string
	tag             string
}

func parseSbomFilters(r *http.Request) (sbomFilters, error) {
	var filters sbomFilters

	if raw := strings.TrimSpace(r.URL.Query().Get("productId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return filters, err
		}
		filters.productID = &parsed
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("scopeId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return filters, err
		}
		filters.scopeID = &parsed
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("testId")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			return filters, err
		}
		filters.testID = &parsed
	}

	if rawType := strings.TrimSpace(r.URL.Query().Get("sbomType")); rawType != "" {
		parsed, _, err := parseSbomTypeField(rawType)
		if err != nil {
			return filters, err
		}
		filters.sbomStandard = string(parsed.Standard)
		filters.sbomSpecVersion = parsed.SpecVersion
	}
	if rawStandard := strings.TrimSpace(r.URL.Query().Get("sbomStandard")); rawStandard != "" {
		standard, err := sbom.NormalizeStandard(rawStandard)
		if err != nil || standard == "" {
			return filters, err
		}
		if filters.sbomStandard != "" && !strings.EqualFold(filters.sbomStandard, string(standard)) {
			return filters, fmt.Errorf("sbomStandard does not match sbomType")
		}
		filters.sbomStandard = string(standard)
	}
	if rawSpec := strings.TrimSpace(r.URL.Query().Get("sbomSpecVersion")); rawSpec != "" {
		spec, err := sbom.NormalizeSpecVersion(rawSpec)
		if err != nil {
			return filters, err
		}
		if filters.sbomSpecVersion != "" && !strings.EqualFold(filters.sbomSpecVersion, spec) {
			return filters, fmt.Errorf("sbomSpecVersion does not match sbomType")
		}
		filters.sbomSpecVersion = spec
	}
	if rawProducer := strings.TrimSpace(r.URL.Query().Get("sbomProducer")); rawProducer != "" {
		producer, _, err := parseSbomProducerField(rawProducer)
		if err != nil {
			return filters, err
		}
		filters.sbomProducer = string(producer)
	}

	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if tag == "" {
		tag = strings.TrimSpace(r.URL.Query().Get("tags"))
	}
	tag, err := validateTagFilter(tag)
	if err != nil {
		return filters, err
	}
	filters.tag = tag

	return filters, nil
}

func hasTag(tags []string, target string) bool {
	if target == "" {
		return false
	}
	for _, tag := range tags {
		if strings.EqualFold(tag, target) {
			return true
		}
	}
	return false
}
