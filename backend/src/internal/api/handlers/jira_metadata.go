package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"backend/internal/core/alerting"
	"backend/internal/models"
	"backend/internal/store"
)

type jiraMetadataResponse struct {
	FromCache bool   `json:"fromCache"`
	BaseURL   string `json:"baseUrl,omitempty"`
	Items     any    `json:"items"`
}

func jiraDefaultPrioritiesMetadata() []alerting.JiraMetadataPriority {
	return []alerting.JiraMetadataPriority{
		{ID: "highest", Name: "Highest"},
		{ID: "high", Name: "High"},
		{ID: "medium", Name: "Medium"},
		{ID: "low", Name: "Low"},
		{ID: "lowest", Name: "Lowest"},
	}
}

func jiraDefaultTransitionsMetadata() []alerting.JiraMetadataTransition {
	return []alerting.JiraMetadataTransition{
		{ID: "todo", Name: "To Do"},
		{ID: "in_progress", Name: "In Progress"},
		{ID: "done", Name: "Done"},
		{ID: "closed", Name: "Closed"},
		{ID: "resolve_issue", Name: "Resolve Issue"},
		{ID: "reopen", Name: "Reopen"},
	}
}

func writeJiraMetadataScopeLimitedFallback(w http.ResponseWriter, items any) {
	writeJSON(w, http.StatusOK, jiraMetadataResponse{
		FromCache: false,
		Items:     items,
	})
}

func parseForceRefresh(raw string) (bool, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return false, nil
	}
	return strconv.ParseBool(value)
}

func resolveJiraConnectorForMetadata(r *http.Request, st store.Store) (*alerting.JiraConnectorProfile, *models.Project, *resolveError) {
	_, project, resolveErr := resolveActiveProject(r, st)
	if resolveErr != nil {
		return nil, nil, resolveErr
	}
	connector, err := st.GetProjectConnectorConfig(project.ID, store.ConnectorTypeJira)
	if err == store.ErrNotFound || connector == nil {
		return nil, nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Jira connector is not configured.",
		}
	}
	if err != nil {
		return nil, nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load Jira connector.",
			err:    err,
		}
	}
	cfg, parseErr := alerting.ParseJiraConnectorProfile(connector.ConfigJSON)
	if parseErr != nil {
		return nil, nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Jira connector profile is invalid: " + parseErr.Error(),
			err:    parseErr,
		}
	}
	return cfg, project, nil
}

func GetJiraMetadataProjectsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraProjectsWithCache(r.Context(), st, project.ID, cfg, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataProject, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataProject, 0))
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira projects metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataIssueTypesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		projectKey := strings.TrimSpace(r.URL.Query().Get("projectKey"))
		if projectKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "projectKey is required.", nil)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraIssueTypesWithCache(r.Context(), st, project.ID, cfg, projectKey, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueType, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueType, 0))
				return
			}
			var statusErr alerting.HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueType, 0))
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira issue types metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataComponentsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		projectKey := strings.TrimSpace(r.URL.Query().Get("projectKey"))
		if projectKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "projectKey is required.", nil)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraProjectComponentsWithCache(r.Context(), st, project.ID, cfg, projectKey, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataComponent, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataComponent, 0))
				return
			}
			var statusErr alerting.HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataComponent, 0))
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira components metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataIssuesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		projectKey := strings.TrimSpace(r.URL.Query().Get("projectKey"))
		if projectKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "projectKey is required.", nil)
			return
		}
		issueTypeName := strings.TrimSpace(r.URL.Query().Get("issueTypeName"))
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraIssuesWithCache(r.Context(), st, project.ID, cfg, projectKey, issueTypeName, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssue, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssue, 0))
				return
			}
			var statusErr alerting.HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssue, 0))
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira issues metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataPrioritiesHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraPrioritiesWithCache(r.Context(), st, project.ID, cfg, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataPriority, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, jiraDefaultPrioritiesMetadata())
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok && statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError {
				writeJiraMetadataScopeLimitedFallback(w, jiraDefaultPrioritiesMetadata())
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira priorities metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataTransitionsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		issueIDOrKey := strings.TrimSpace(r.URL.Query().Get("issueIdOrKey"))
		if issueIDOrKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "issueIdOrKey is required.", nil)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraTransitionsWithCache(r.Context(), st, project.ID, cfg, issueIDOrKey, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, jiraDefaultTransitionsMetadata())
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, jiraDefaultTransitionsMetadata())
				return
			}
			var statusErr alerting.HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
				writeJiraMetadataScopeLimitedFallback(w, jiraDefaultTransitionsMetadata())
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira transitions metadata.", err)
			return
		}
		if len(items) == 0 {
			items = jiraDefaultTransitionsMetadata()
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}

func GetJiraMetadataIssueFieldsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, project, resolveErr := resolveJiraConnectorForMetadata(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		projectKey := strings.TrimSpace(r.URL.Query().Get("projectKey"))
		if projectKey == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "projectKey is required.", nil)
			return
		}
		issueTypeID := strings.TrimSpace(r.URL.Query().Get("issueTypeId"))
		if issueTypeID == "" {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "issueTypeId is required.", nil)
			return
		}
		forceRefresh, parseErr := parseForceRefresh(r.URL.Query().Get("forceRefresh"))
		if parseErr != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid forceRefresh query value.", parseErr)
			return
		}
		items, fromCache, err := alerting.LoadJiraIssueFieldsWithCache(r.Context(), st, project.ID, cfg, projectKey, issueTypeID, forceRefresh)
		if err != nil {
			if alerting.IsJiraAuthScopeMismatch(err) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueField, 0))
				return
			}
			if statusCode, ok := alerting.ParseHTTPStatusCode(err); ok &&
				(statusCode == http.StatusForbidden || statusCode == http.StatusUnauthorized) {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueField, 0))
				return
			}
			var statusErr alerting.HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
				writeJiraMetadataScopeLimitedFallback(w, make([]alerting.JiraMetadataIssueField, 0))
				return
			}
			writeProblem(w, r, http.StatusBadGateway, "Integration Error", "Failed to fetch Jira issue fields metadata.", err)
			return
		}
		writeJSON(w, http.StatusOK, jiraMetadataResponse{FromCache: fromCache, BaseURL: cfg.BaseURL, Items: items})
	}
}
