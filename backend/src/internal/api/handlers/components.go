package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"backend/internal/store"

	"github.com/google/uuid"
)

type componentListItem struct {
	ID                      uuid.UUID       `json:"id"`
	RevisionID              uuid.UUID       `json:"revisionId"`
	PURL                    string          `json:"purl"`
	PkgName                 string          `json:"pkgName"`
	Version                 string          `json:"version"`
	PkgType                 string          `json:"pkgType"`
	PkgNamespace            string          `json:"pkgNamespace,omitempty"`
	SbomType                string          `json:"sbomType,omitempty"`
	Publisher               string          `json:"publisher,omitempty"`
	Supplier                string          `json:"supplier,omitempty"`
	Licenses                json.RawMessage `json:"licenses,omitempty"`
	Properties              json.RawMessage `json:"properties,omitempty"`
	CreatedAt               time.Time       `json:"createdAt"`
	MalwareVerdict          string          `json:"malwareVerdict,omitempty"`
	MalwareFindingsCount    int             `json:"malwareFindingsCount,omitempty"`
	MalwareTriageStatus     string          `json:"malwareTriageStatus,omitempty"`
	MalwareScannedAt        *time.Time      `json:"malwareScannedAt,omitempty"`
	MalwareValidUntil       *time.Time      `json:"malwareValidUntil,omitempty"`
	MalwarePURLs            []string        `json:"malwarePurls,omitempty"`
	MalwareQueueStatus      string          `json:"malwareQueueStatus,omitempty"`
	MalwareQueueCompletedAt *time.Time      `json:"malwareQueueCompletedAt,omitempty"`
}

const maxComponentsListAllLimit = 1_000_000

// ListComponentsHandler returns a paginated list of components for a test.
func ListComponentsHandler(memStore store.Store) http.HandlerFunc {
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
		if raw := strings.TrimSpace(r.URL.Query().Get("all")); raw != "" {
			all, parseErr := strconv.ParseBool(raw)
			if parseErr != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid 'all' parameter.", parseErr)
				return
			}
			if all {
				page = 1
				pageSize = maxComponentsListAllLimit
			}
		}

		query, err := parseOptionalQuery(r.URL.Query().Get("q"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		pkgNameFilter, err := parseComponentFilter(r, "pkgName")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		if pkgNameFilter == "" {
			pkgNameFilter, err = parseComponentFilter(r, "name")
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
				return
			}
		}
		purlFilter, err := parseComponentFilter(r, "purl")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		pkgTypeFilter, err := parseComponentFilter(r, "pkgType")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		if pkgTypeFilter == "" {
			pkgTypeFilter, err = parseComponentFilter(r, "type")
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
				return
			}
		}
		pkgNamespaceFilter, err := parseComponentFilter(r, "pkgNamespace")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		if pkgNamespaceFilter == "" {
			pkgNamespaceFilter, err = parseComponentFilter(r, "namespace")
			if err != nil {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
				return
			}
		}
		versionFilter, err := parseComponentFilter(r, "version")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		sbomTypeFilter, err := parseComponentFilter(r, "sbomType")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		publisherFilter, err := parseComponentFilter(r, "publisher")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}
		supplierFilter, err := parseComponentFilter(r, "supplier")
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}

		sortField, sortDesc, err := parseComponentSort(r.URL.Query().Get("sort"))
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error(), err)
			return
		}

		offset := (page - 1) * pageSize
		filter := store.ComponentListFilter{
			Query:        query,
			PkgName:      pkgNameFilter,
			PURL:         purlFilter,
			PkgType:      pkgTypeFilter,
			PkgNamespace: pkgNamespaceFilter,
			Version:      versionFilter,
			SbomType:     sbomTypeFilter,
			Publisher:    publisherFilter,
			Supplier:     supplierFilter,
		}
		components, err := memStore.ListComponentsPage(
			testID,
			filter,
			store.ComponentListSort{Field: sortField, Desc: sortDesc},
			pageSize,
			offset,
		)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Test not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to list components.", err)
			return
		}

		results := make([]componentListItem, 0, len(components))
		for _, component := range components {
			results = append(results, componentListItem{
				ID:                      component.ID,
				RevisionID:              component.RevisionID,
				PURL:                    component.PURL,
				PkgName:                 component.PkgName,
				Version:                 component.Version,
				PkgType:                 component.PkgType,
				PkgNamespace:            component.PkgNamespace,
				SbomType:                component.SbomType,
				Publisher:               component.Publisher,
				Supplier:                component.Supplier,
				Licenses:                component.Licenses,
				Properties:              component.Properties,
				MalwareVerdict:          component.MalwareVerdict,
				MalwareFindingsCount:    component.MalwareFindingsCount,
				MalwareTriageStatus:     component.MalwareTriageStatus,
				MalwareScannedAt:        component.MalwareScannedAt,
				MalwareValidUntil:       component.MalwareValidUntil,
				MalwarePURLs:            component.MalwarePURLs,
				MalwareQueueStatus:      component.MalwareQueueStatus,
				MalwareQueueCompletedAt: component.MalwareQueueCompletedAt,
				CreatedAt:               component.CreatedAt,
			})
		}

		writeJSON(w, http.StatusOK, results)
	}
}

// GetComponentHandler returns component details for a test.
func GetComponentHandler(memStore store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, memStore)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}

		rawTestID := r.PathValue("testId")
		testID, err := uuid.Parse(rawTestID)
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
		rawComponentID := r.PathValue("componentId")
		componentID, err := uuid.Parse(rawComponentID)
		if err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid componentId.", err)
			return
		}

		component, err := memStore.GetComponent(testID, componentID)
		if err == store.ErrNotFound {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "Component not found.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load component.", err)
			return
		}

		writeJSON(w, http.StatusOK, component)
	}
}

func parseOptionalQuery(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	return validateSearchQuery(raw)
}

func parseComponentFilter(r *http.Request, key string) (string, error) {
	raw := r.URL.Query().Get(key)
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	clean := sanitizePlainText(raw)
	if clean == "" {
		return "", fmt.Errorf("query parameter '%s' must not be empty", key)
	}
	if utf8.RuneCountInString(clean) > maxSearchQueryRunes {
		return "", fmt.Errorf("query parameter '%s' must be at most %d characters", key, maxSearchQueryRunes)
	}
	return clean, nil
}

func parseComponentSort(raw string) (string, bool, error) {
	clean := sanitizePlainText(raw)
	if clean == "" {
		return "pkgName", false, nil
	}
	desc := strings.HasPrefix(clean, "-")
	field := strings.TrimPrefix(clean, "-")
	switch field {
	case "name":
		return "pkgName", desc, nil
	case "type":
		return "pkgType", desc, nil
	case "namespace":
		return "pkgNamespace", desc, nil
	case "pkgName", "pkgType", "pkgNamespace", "sbomType", "publisher", "supplier", "createdAt", "purl", "version":
		return field, desc, nil
	default:
		return "", false, fmt.Errorf("query parameter 'sort' must be one of pkgName, pkgType, pkgNamespace, sbomType, publisher, supplier, createdAt, purl, version")
	}
}
