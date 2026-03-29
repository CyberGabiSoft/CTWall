package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type JiraIssueUpsertPayload struct {
	ProjectKey   string
	IssueType    string
	Summary      string
	Description  string
	Labels       []string
	Components   []string
	PriorityName string
	IssueFields  map[string]any
}

type JiraIssueReference struct {
	ID  string
	Key string
}

type jiraTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraMetadataProject struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type JiraMetadataIssueType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraMetadataComponent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraMetadataPriority struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraMetadataIssue struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Summary string `json:"summary"`
	Status  string `json:"status"`
}

type JiraMetadataTransition struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type JiraMetadataIssueFieldOption struct {
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type JiraMetadataIssueField struct {
	Key           string                         `json:"key"`
	Name          string                         `json:"name"`
	Required      bool                           `json:"required"`
	InputType     string                         `json:"inputType"` // text|number|boolean|single_select|multi_select
	AllowedValues []JiraMetadataIssueFieldOption `json:"allowedValues,omitempty"`
}

type JiraIssueStatusSnapshot struct {
	IssueID           string
	IssueKey          string
	StatusName        string
	StatusCategoryKey string
	ResolutionName    string
}

const (
	jiraEpicIssueKeyField = "__ctwall_epic_issue_key"
	jiraEpicFieldKeyField = "__ctwall_epic_field_key"
	jiraEpicModeField     = "__ctwall_epic_mode"
	jiraEpicCreateSummary = "__ctwall_epic_create_summary"
	jiraEpicCreateType    = "__ctwall_epic_create_issue_type"
)

type jiraEpicMode string

const (
	jiraEpicModeNone     jiraEpicMode = "none"
	jiraEpicModeExisting jiraEpicMode = "existing"
	jiraEpicModeCreate   jiraEpicMode = "create"
)

type jiraEpicConfig struct {
	Mode            jiraEpicMode
	IssueKey        string
	FieldKey        string
	CreateSummary   string
	CreateIssueType string
}

func jiraHTTPClient(timeoutSeconds int) *http.Client {
	timeout := 10 * time.Second
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func jiraAPIVersions(mode JiraDeploymentMode) []int {
	switch mode {
	case JiraDeploymentCloud:
		return []int{3}
	case JiraDeploymentDataCenter:
		return []int{2}
	default:
		return []int{3, 2}
	}
}

func jiraDoJSON(
	ctx context.Context,
	cfg *JiraConnectorProfile,
	client *http.Client,
	method string,
	pathTemplate string,
	body any,
	okStatuses ...int,
) ([]byte, int, error) {
	if cfg == nil {
		return nil, 0, errors.New("jira config is nil")
	}
	if client == nil {
		client = jiraHTTPClient(cfg.RequestTimeoutSeconds)
	}
	authMethods := jiraAuthMethods(cfg)
	if len(authMethods) == 0 {
		return nil, 0, errors.New("jira auth config is empty")
	}
	baseURLs := jiraCandidateBaseURLs(ctx, cfg, client)
	if len(baseURLs) == 0 {
		baseURLs = []string{strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")}
	}

	var payloadBytes []byte
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		payloadBytes = raw
	}

	var lastErr error
	versions := jiraAPIVersions(cfg.DeploymentMode)
	for baseIdx := range baseURLs {
		baseURL := baseURLs[baseIdx]
		retryNextBase := false
		for idx, version := range versions {
			targetURL := strings.TrimRight(baseURL, "/") + fmt.Sprintf(pathTemplate, version)
			statusCode, respBody, err := jiraDoRequestWithAuthFallback(client, func() (*http.Request, error) {
				var requestBody io.Reader
				if payloadBytes != nil {
					requestBody = bytes.NewReader(payloadBytes)
				}
				req, buildErr := http.NewRequestWithContext(ctx, method, targetURL, requestBody)
				if buildErr != nil {
					return nil, buildErr
				}
				req.Header.Set("Accept", "application/json")
				if payloadBytes != nil {
					req.Header.Set("Content-Type", "application/json")
				}
				return req, nil
			}, authMethods, 2*1024*1024)
			if err != nil {
				if statusCode, ok := ParseHTTPStatusCode(err); ok &&
					(statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
					baseIdx < len(baseURLs)-1 {
					// Service-account setups can authenticate only on one of candidate base URLs.
					// Try the next candidate instead of failing immediately on the first auth error.
					lastErr = err
					retryNextBase = true
					break
				}
				return nil, 0, err
			}

			ok := false
			for _, status := range okStatuses {
				if statusCode == status {
					ok = true
					break
				}
			}
			if ok {
				return respBody, version, nil
			}

			if statusCode == http.StatusNotFound && cfg.DeploymentMode == JiraDeploymentAuto && idx < len(versions)-1 {
				lastErr = HTTPStatusError{StatusCode: statusCode, Body: strings.TrimSpace(string(respBody))}
				continue
			}
			if (statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden) &&
				jiraScopeMismatchBody(respBody) &&
				baseIdx < len(baseURLs)-1 {
				lastErr = HTTPStatusError{StatusCode: statusCode, Body: strings.TrimSpace(string(respBody))}
				retryNextBase = true
				break
			}
			return nil, version, HTTPStatusError{StatusCode: statusCode, Body: strings.TrimSpace(string(respBody))}
		}
		if retryNextBase {
			continue
		}
	}
	if lastErr != nil {
		return nil, 0, lastErr
	}
	return nil, 0, errors.New("jira request failed")
}

func jiraDescriptionForVersion(text string, version int) any {
	content := strings.TrimSpace(text)
	if content == "" {
		content = "No details."
	}
	if version <= 2 {
		return content
	}
	// Jira Cloud v3 (ADF).
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": []map[string]any{
			{
				"type": "paragraph",
				"content": []map[string]any{
					{
						"type": "text",
						"text": content,
					},
				},
			},
		},
	}
}

func jiraIssueFields(payload JiraIssueUpsertPayload, version int) map[string]any {
	fields := map[string]any{
		"project":     map[string]any{"key": strings.TrimSpace(payload.ProjectKey)},
		"issuetype":   map[string]any{"name": strings.TrimSpace(payload.IssueType)},
		"summary":     strings.TrimSpace(payload.Summary),
		"description": jiraDescriptionForVersion(payload.Description, version),
	}
	if labels := sanitizeJiraLabels(payload.Labels); len(labels) > 0 {
		fields["labels"] = labels
	}
	if components := sanitizeJiraLabels(payload.Components); len(components) > 0 {
		items := make([]map[string]any, 0, len(components))
		for _, component := range components {
			items = append(items, map[string]any{"name": component})
		}
		fields["components"] = items
	}
	if priority := strings.TrimSpace(payload.PriorityName); priority != "" {
		fields["priority"] = map[string]any{"name": priority}
	}
	epicCfg := parseJiraEpicConfig(payload.IssueFields)
	if len(payload.IssueFields) > 0 {
		for rawKey, value := range payload.IssueFields {
			key := strings.TrimSpace(rawKey)
			if key == "" {
				continue
			}
			if isInternalJiraIssueFieldKey(key) {
				continue
			}
			lower := strings.ToLower(key)
			if lower == "project" || lower == "issuetype" || lower == "summary" ||
				lower == "description" || lower == "priority" || lower == "labels" || lower == "components" {
				continue
			}
			fields[key] = value
		}
	}
	if epicCfg.IssueKey != "" {
		// Backward compatibility: missing mode with explicit issue key behaves as "existing".
		if epicCfg.Mode == jiraEpicModeNone {
			epicCfg.Mode = jiraEpicModeExisting
		}
		if epicCfg.Mode == jiraEpicModeExisting || epicCfg.Mode == jiraEpicModeCreate {
			if epicCfg.FieldKey == "" || strings.EqualFold(epicCfg.FieldKey, "parent") {
				fields["parent"] = map[string]any{"key": epicCfg.IssueKey}
			} else {
				fields[epicCfg.FieldKey] = epicCfg.IssueKey
			}
		}
	}
	return fields
}

func parseJiraEpicConfig(issueFields map[string]any) jiraEpicConfig {
	cfg := jiraEpicConfig{
		Mode:            jiraEpicModeNone,
		IssueKey:        "",
		FieldKey:        "",
		CreateSummary:   "",
		CreateIssueType: "",
	}
	if len(issueFields) == 0 {
		return cfg
	}
	cfg.Mode = normalizeJiraEpicMode(strings.TrimSpace(toString(issueFields[jiraEpicModeField])))
	cfg.IssueKey = strings.TrimSpace(toString(issueFields[jiraEpicIssueKeyField]))
	cfg.FieldKey = strings.TrimSpace(toString(issueFields[jiraEpicFieldKeyField]))
	cfg.CreateSummary = strings.TrimSpace(toString(issueFields[jiraEpicCreateSummary]))
	cfg.CreateIssueType = strings.TrimSpace(toString(issueFields[jiraEpicCreateType]))
	if cfg.Mode == jiraEpicModeNone && cfg.IssueKey != "" {
		cfg.Mode = jiraEpicModeExisting
	}
	return cfg
}

func normalizeJiraEpicMode(raw string) jiraEpicMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(jiraEpicModeExisting):
		return jiraEpicModeExisting
	default:
		return jiraEpicModeNone
	}
}

func isInternalJiraIssueFieldKey(key string) bool {
	switch strings.TrimSpace(key) {
	case jiraEpicIssueKeyField, jiraEpicFieldKeyField, jiraEpicModeField, jiraEpicCreateSummary, jiraEpicCreateType:
		return true
	default:
		return false
	}
}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func sanitizeJiraLabels(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		item := strings.TrimSpace(value)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func JiraCreateIssue(ctx context.Context, cfg *JiraConnectorProfile, payload JiraIssueUpsertPayload) (*JiraIssueReference, error) {
	client := jiraHTTPClient(cfg.RequestTimeoutSeconds)
	versions := jiraAPIVersions(cfg.DeploymentMode)
	var lastErr error
	for _, version := range versions {
		body := map[string]any{"fields": jiraIssueFields(payload, version)}
		respBody, _, err := jiraDoJSON(ctx, cfg, client, http.MethodPost, "/rest/api/%d/issue", body, http.StatusCreated, http.StatusOK)
		if err != nil {
			var statusErr HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound && cfg.DeploymentMode == JiraDeploymentAuto {
				lastErr = err
				continue
			}
			return nil, err
		}
		var parsed struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		if unmarshalErr := json.Unmarshal(respBody, &parsed); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		parsed.ID = strings.TrimSpace(parsed.ID)
		parsed.Key = strings.TrimSpace(parsed.Key)
		if parsed.ID == "" && parsed.Key == "" {
			return nil, errors.New("jira create issue response missing id/key")
		}
		return &JiraIssueReference{ID: parsed.ID, Key: parsed.Key}, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("jira create issue failed")
}

func JiraUpdateIssue(ctx context.Context, cfg *JiraConnectorProfile, issueIDOrKey string, payload JiraIssueUpsertPayload) error {
	issueIDOrKey = strings.TrimSpace(issueIDOrKey)
	if issueIDOrKey == "" {
		return errors.New("jira issue id/key is required")
	}
	client := jiraHTTPClient(cfg.RequestTimeoutSeconds)
	versions := jiraAPIVersions(cfg.DeploymentMode)
	var lastErr error
	for _, version := range versions {
		body := map[string]any{"fields": jiraIssueFields(payload, version)}
		_, _, err := jiraDoJSON(
			ctx,
			cfg,
			client,
			http.MethodPut,
			"/rest/api/%d/issue/"+issueIDOrKey,
			body,
			http.StatusNoContent,
			http.StatusOK,
			http.StatusAccepted,
		)
		if err != nil {
			var statusErr HTTPStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound && cfg.DeploymentMode == JiraDeploymentAuto {
				lastErr = err
				continue
			}
			return err
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("jira update issue failed")
}

func resolveTransitionIDByName(transitions []jiraTransition, preferredName string) string {
	name := strings.TrimSpace(preferredName)
	if name == "" {
		defaultNames := []string{"Done", "Closed", "Resolve Issue", "Resolved"}
		for _, candidate := range defaultNames {
			for _, item := range transitions {
				if strings.EqualFold(strings.TrimSpace(item.Name), candidate) {
					return strings.TrimSpace(item.ID)
				}
			}
		}
		return ""
	}
	for _, item := range transitions {
		if strings.EqualFold(strings.TrimSpace(item.Name), name) {
			return strings.TrimSpace(item.ID)
		}
	}
	return ""
}

func jiraListTransitions(ctx context.Context, cfg *JiraConnectorProfile, issueIDOrKey string) ([]jiraTransition, int, error) {
	respBody, version, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/issue/"+issueIDOrKey+"/transitions",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, version, err
	}
	var parsed struct {
		Transitions []jiraTransition `json:"transitions"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, version, err
	}
	return parsed.Transitions, version, nil
}

func JiraGetIssueStatusSnapshot(ctx context.Context, cfg *JiraConnectorProfile, issueIDOrKey string) (*JiraIssueStatusSnapshot, error) {
	issueIDOrKey = strings.TrimSpace(issueIDOrKey)
	if issueIDOrKey == "" {
		return nil, errors.New("jira issue id/key is required")
	}
	escapedIssueIDOrKey := strings.ReplaceAll(url.PathEscape(issueIDOrKey), "%", "%%")
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/issue/"+escapedIssueIDOrKey+"?fields=status,resolution",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Status *struct {
				Name           string `json:"name"`
				StatusCategory *struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
			Resolution *struct {
				Name string `json:"name"`
			} `json:"resolution"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}
	if parsed.Fields.Status == nil {
		return nil, errors.New("jira issue response missing status field")
	}

	out := &JiraIssueStatusSnapshot{
		IssueID:    strings.TrimSpace(parsed.ID),
		IssueKey:   strings.TrimSpace(parsed.Key),
		StatusName: strings.TrimSpace(parsed.Fields.Status.Name),
	}
	if parsed.Fields.Status.StatusCategory != nil {
		out.StatusCategoryKey = strings.TrimSpace(parsed.Fields.Status.StatusCategory.Key)
	}
	if parsed.Fields.Resolution != nil {
		out.ResolutionName = strings.TrimSpace(parsed.Fields.Resolution.Name)
	}
	return out, nil
}

func jiraIssueIsClosed(snapshot *JiraIssueStatusSnapshot) bool {
	if snapshot == nil {
		return false
	}
	statusCategoryKey := strings.ToLower(strings.TrimSpace(snapshot.StatusCategoryKey))
	if statusCategoryKey == "done" {
		return true
	}
	if statusCategoryKey != "" {
		// Jira may keep resolution populated on reopened issues.
		// If category is explicitly not "done", do not treat it as closed.
		return false
	}
	statusName := strings.ToLower(strings.TrimSpace(snapshot.StatusName))
	switch statusName {
	case "done", "closed", "resolved", "complete", "completed":
		return true
	default:
		// Fallback only when Jira did not provide status category and status name.
		return statusName == "" && strings.TrimSpace(snapshot.ResolutionName) != ""
	}
}

func JiraListProjects(ctx context.Context, cfg *JiraConnectorProfile) ([]JiraMetadataProject, error) {
	client := jiraHTTPClient(cfg.RequestTimeoutSeconds)
	type jiraProjectItem struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	type jiraProjectSearchResponse struct {
		StartAt   int               `json:"startAt"`
		MaxResult int               `json:"maxResults"`
		Total     int               `json:"total"`
		IsLast    bool              `json:"isLast"`
		Values    []jiraProjectItem `json:"values"`
	}

	collected := make([]jiraProjectItem, 0, 128)
	const pageSize = 100
	startAt := 0
	for {
		pathTemplate := fmt.Sprintf("/rest/api/%%d/project/search?maxResults=%d&startAt=%d", pageSize, startAt)
		respBody, _, err := jiraDoJSON(
			ctx,
			cfg,
			client,
			http.MethodGet,
			pathTemplate,
			nil,
			http.StatusOK,
		)
		if err != nil {
			return nil, err
		}

		var parsed jiraProjectSearchResponse
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, err
		}
		collected = append(collected, parsed.Values...)

		if parsed.IsLast || len(parsed.Values) == 0 {
			break
		}
		startAt += len(parsed.Values)
		if parsed.Total > 0 && startAt >= parsed.Total {
			break
		}
	}

	out := make([]JiraMetadataProject, 0, len(collected))
	seen := make(map[string]struct{}, len(collected))
	for _, item := range collected {
		project := JiraMetadataProject{
			ID:   strings.TrimSpace(item.ID),
			Key:  strings.TrimSpace(item.Key),
			Name: strings.TrimSpace(item.Name),
		}
		if project.Key == "" {
			continue
		}
		key := strings.ToUpper(project.Key)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, project)
	}
	return out, nil
}

func jiraGetProject(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataIssueType, []JiraMetadataComponent, error) {
	key := strings.TrimSpace(projectKey)
	if key == "" {
		return nil, nil, errors.New("jira project key is required")
	}
	escapedKey := strings.ReplaceAll(url.PathEscape(key), "%", "%%")

	var (
		issueTypes []JiraMetadataIssueType
		components []JiraMetadataComponent
		firstErr   error
	)

	// Preferred path: project details with expanded issue types.
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/project/"+escapedKey+"?expand=issueTypes",
		nil,
		http.StatusOK,
	)
	if err == nil {
		var parsed struct {
			IssueTypes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"issueTypes"`
			Components []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"components"`
		}
		if parseErr := json.Unmarshal(respBody, &parsed); parseErr == nil {
			issueTypes = make([]JiraMetadataIssueType, 0, len(parsed.IssueTypes))
			for _, item := range parsed.IssueTypes {
				issueType := JiraMetadataIssueType{
					ID:   strings.TrimSpace(item.ID),
					Name: strings.TrimSpace(item.Name),
				}
				if issueType.Name == "" {
					continue
				}
				issueTypes = append(issueTypes, issueType)
			}
			components = make([]JiraMetadataComponent, 0, len(parsed.Components))
			for _, item := range parsed.Components {
				component := JiraMetadataComponent{
					ID:   strings.TrimSpace(item.ID),
					Name: strings.TrimSpace(item.Name),
				}
				if component.Name == "" {
					continue
				}
				components = append(components, component)
			}
		} else {
			firstErr = parseErr
		}
	} else {
		firstErr = err
	}

	// Fallback for Jira Cloud/service accounts: issue types are available via project statuses.
	if len(issueTypes) == 0 {
		if fallback, fallbackErr := jiraListIssueTypesFromProjectStatuses(ctx, cfg, key); fallbackErr == nil && len(fallback) > 0 {
			issueTypes = fallback
		} else if firstErr == nil {
			firstErr = fallbackErr
		}
	}
	// Some Jira setups expose issue type data only through issue search payloads.
	if len(issueTypes) == 0 {
		if fallback, fallbackErr := jiraListIssueTypesFromProjectIssues(ctx, cfg, key); fallbackErr == nil && len(fallback) > 0 {
			issueTypes = fallback
		} else if firstErr == nil && fallbackErr != nil {
			firstErr = fallbackErr
		}
	}
	// Last-resort fallback: list global issue types visible to the authenticated user.
	if len(issueTypes) == 0 {
		if fallback, fallbackErr := jiraListIssueTypesGlobal(ctx, cfg); fallbackErr == nil && len(fallback) > 0 {
			issueTypes = fallback
		} else if firstErr == nil && fallbackErr != nil {
			firstErr = fallbackErr
		}
	}
	// Components are also available from a dedicated endpoint.
	if len(components) == 0 {
		if fallback, fallbackErr := jiraListProjectComponentsByProject(ctx, cfg, key); fallbackErr == nil {
			components = fallback
		} else if firstErr == nil {
			firstErr = fallbackErr
		}
	}

	if len(issueTypes) == 0 && len(components) == 0 && firstErr != nil {
		return nil, nil, firstErr
	}
	return issueTypes, components, nil
}

func jiraListIssueTypesFromProjectStatuses(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataIssueType, error) {
	key := strings.TrimSpace(projectKey)
	if key == "" {
		return nil, errors.New("jira project key is required")
	}
	escapedKey := strings.ReplaceAll(url.PathEscape(key), "%", "%%")
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/project/"+escapedKey+"/statuses",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	type issueTypeItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	type issueTypeStatusItem struct {
		ID        string         `json:"id"`
		Name      string         `json:"name"`
		IssueType *issueTypeItem `json:"issueType"`
	}
	var items []issueTypeStatusItem
	if unmarshalErr := json.Unmarshal(respBody, &items); unmarshalErr != nil {
		var wrapped struct {
			Values     []issueTypeStatusItem `json:"values"`
			IssueTypes []issueTypeStatusItem `json:"issueTypes"`
		}
		if wrappedErr := json.Unmarshal(respBody, &wrapped); wrappedErr != nil {
			return nil, unmarshalErr
		}
		if len(wrapped.Values) > 0 {
			items = wrapped.Values
		} else {
			items = wrapped.IssueTypes
		}
	}

	out := make([]JiraMetadataIssueType, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		name := strings.TrimSpace(item.Name)
		if (id == "" || name == "") && item.IssueType != nil {
			if id == "" {
				id = strings.TrimSpace(item.IssueType.ID)
			}
			if name == "" {
				name = strings.TrimSpace(item.IssueType.Name)
			}
		}
		if name == "" {
			continue
		}
		key := strings.ToLower(id + "|" + name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, JiraMetadataIssueType{ID: id, Name: name})
	}
	return out, nil
}

func jiraListIssueTypesFromProjectIssues(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataIssueType, error) {
	key := strings.TrimSpace(projectKey)
	if key == "" {
		return nil, errors.New("jira project key is required")
	}

	jql := `project = "` + strings.ReplaceAll(key, `"`, `\"`) + `" ORDER BY updated DESC`
	escapedJQL := strings.ReplaceAll(url.QueryEscape(jql), "%", "%%")
	escapedFields := strings.ReplaceAll(url.QueryEscape("issuetype"), "%", "%%")
	pathTemplateJQL := fmt.Sprintf(
		"/rest/api/%%d/search/jql?jql=%s&fields=%s&maxResults=100&startAt=0",
		escapedJQL,
		escapedFields,
	)
	pathTemplateLegacy := fmt.Sprintf(
		"/rest/api/%%d/search?jql=%s&fields=%s&maxResults=100&startAt=0",
		escapedJQL,
		escapedFields,
	)

	parseIssueTypes := func(raw []byte) ([]JiraMetadataIssueType, error) {
		var parsed struct {
			Issues []struct {
				Fields struct {
					IssueType struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"issuetype"`
				} `json:"fields"`
			} `json:"issues"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}

		out := make([]JiraMetadataIssueType, 0, len(parsed.Issues))
		seen := make(map[string]struct{}, len(parsed.Issues))
		for _, issue := range parsed.Issues {
			id := strings.TrimSpace(issue.Fields.IssueType.ID)
			name := strings.TrimSpace(issue.Fields.IssueType.Name)
			if name == "" {
				continue
			}
			seenKey := strings.ToLower(id + "|" + name)
			if _, exists := seen[seenKey]; exists {
				continue
			}
			seen[seenKey] = struct{}{}
			out = append(out, JiraMetadataIssueType{ID: id, Name: name})
		}
		return out, nil
	}

	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		pathTemplateJQL,
		nil,
		http.StatusOK,
	)
	if err == nil {
		return parseIssueTypes(respBody)
	}
	if statusCode, ok := ParseHTTPStatusCode(err); ok && statusCode == http.StatusNotFound {
		respBody, _, legacyErr := jiraDoJSON(
			ctx,
			cfg,
			jiraHTTPClient(cfg.RequestTimeoutSeconds),
			http.MethodGet,
			pathTemplateLegacy,
			nil,
			http.StatusOK,
		)
		if legacyErr != nil {
			return nil, legacyErr
		}
		return parseIssueTypes(respBody)
	}
	return nil, err
}

func jiraListIssueTypesGlobal(ctx context.Context, cfg *JiraConnectorProfile) ([]JiraMetadataIssueType, error) {
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/issuetype",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	type issueTypeItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var items []issueTypeItem
	if unmarshalErr := json.Unmarshal(respBody, &items); unmarshalErr != nil {
		var wrapped struct {
			Values []issueTypeItem `json:"values"`
		}
		if wrappedErr := json.Unmarshal(respBody, &wrapped); wrappedErr != nil {
			return nil, unmarshalErr
		}
		items = wrapped.Values
	}

	out := make([]JiraMetadataIssueType, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		seenKey := strings.ToLower(id + "|" + name)
		if _, exists := seen[seenKey]; exists {
			continue
		}
		seen[seenKey] = struct{}{}
		out = append(out, JiraMetadataIssueType{ID: id, Name: name})
	}
	return out, nil
}

func jiraListProjectComponentsByProject(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataComponent, error) {
	key := strings.TrimSpace(projectKey)
	if key == "" {
		return nil, errors.New("jira project key is required")
	}
	escapedKey := strings.ReplaceAll(url.PathEscape(key), "%", "%%")
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/project/"+escapedKey+"/components?startAt=0&maxResults=1000",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	type componentItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	var items []componentItem
	if unmarshalErr := json.Unmarshal(respBody, &items); unmarshalErr != nil {
		var wrapped struct {
			Values     []componentItem `json:"values"`
			Components []componentItem `json:"components"`
		}
		if wrappedErr := json.Unmarshal(respBody, &wrapped); wrappedErr != nil {
			return nil, unmarshalErr
		}
		if len(wrapped.Values) > 0 {
			items = wrapped.Values
		} else {
			items = wrapped.Components
		}
	}

	out := make([]JiraMetadataComponent, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		id := strings.TrimSpace(item.ID)
		key := strings.ToLower(id + "|" + name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, JiraMetadataComponent{ID: id, Name: name})
	}
	return out, nil
}

func JiraListIssueTypes(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataIssueType, error) {
	issueTypes, _, err := jiraGetProject(ctx, cfg, projectKey)
	return issueTypes, err
}

func JiraListProjectComponents(ctx context.Context, cfg *JiraConnectorProfile, projectKey string) ([]JiraMetadataComponent, error) {
	_, components, err := jiraGetProject(ctx, cfg, projectKey)
	return components, err
}

func JiraListProjectIssues(ctx context.Context, cfg *JiraConnectorProfile, projectKey string, maxResults int, issueTypeName string) ([]JiraMetadataIssue, error) {
	key := strings.TrimSpace(projectKey)
	if key == "" {
		return nil, errors.New("jira project key is required")
	}
	if maxResults <= 0 {
		maxResults = 50
	}
	if maxResults > 100 {
		maxResults = 100
	}

	jqlBuilder := strings.Builder{}
	jqlBuilder.WriteString(`project = "`)
	jqlBuilder.WriteString(strings.ReplaceAll(key, `"`, `\"`))
	jqlBuilder.WriteString(`"`)
	if issueType := strings.TrimSpace(issueTypeName); issueType != "" {
		jqlBuilder.WriteString(` AND issuetype = "`)
		jqlBuilder.WriteString(strings.ReplaceAll(issueType, `"`, `\"`))
		jqlBuilder.WriteString(`"`)
	}
	jqlBuilder.WriteString(` ORDER BY updated DESC`)
	jql := jqlBuilder.String()
	escapedJQL := strings.ReplaceAll(url.QueryEscape(jql), "%", "%%")
	escapedFields := strings.ReplaceAll(url.QueryEscape("summary,status"), "%", "%%")
	pathTemplateJQL := fmt.Sprintf(
		"/rest/api/%%d/search/jql?jql=%s&fields=%s&maxResults=%d&startAt=0",
		escapedJQL,
		escapedFields,
		maxResults,
	)
	pathTemplateLegacy := fmt.Sprintf(
		"/rest/api/%%d/search?jql=%s&fields=%s&maxResults=%d&startAt=0",
		escapedJQL,
		escapedFields,
		maxResults,
	)

	parseIssues := func(raw []byte) ([]JiraMetadataIssue, error) {
		var parsed struct {
			Issues []struct {
				ID     string `json:"id"`
				Key    string `json:"key"`
				Fields struct {
					Summary string `json:"summary"`
					Status  struct {
						Name string `json:"name"`
					} `json:"status"`
				} `json:"fields"`
			} `json:"issues"`
		}
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return nil, err
		}

		out := make([]JiraMetadataIssue, 0, len(parsed.Issues))
		for _, item := range parsed.Issues {
			issue := JiraMetadataIssue{
				ID:      strings.TrimSpace(item.ID),
				Key:     strings.TrimSpace(item.Key),
				Summary: strings.TrimSpace(item.Fields.Summary),
				Status:  strings.TrimSpace(item.Fields.Status.Name),
			}
			if issue.Key == "" {
				continue
			}
			out = append(out, issue)
		}
		return out, nil
	}

	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		pathTemplateJQL,
		nil,
		http.StatusOK,
	)
	if err == nil {
		return parseIssues(respBody)
	}

	statusCode, ok := ParseHTTPStatusCode(err)
	if !ok || (statusCode != http.StatusNotFound && statusCode != http.StatusMethodNotAllowed && statusCode != http.StatusBadRequest && statusCode != http.StatusGone) {
		return nil, err
	}

	respBody, _, err = jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		pathTemplateLegacy,
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	return parseIssues(respBody)
}

func JiraListPriorities(ctx context.Context, cfg *JiraConnectorProfile) ([]JiraMetadataPriority, error) {
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		"/rest/api/%d/priority",
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}
	var parsed []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}
	out := make([]JiraMetadataPriority, 0, len(parsed))
	for _, item := range parsed {
		priority := JiraMetadataPriority{
			ID:   strings.TrimSpace(item.ID),
			Name: strings.TrimSpace(item.Name),
		}
		if priority.Name == "" {
			continue
		}
		out = append(out, priority)
	}
	return out, nil
}

func classifyJiraIssueFieldInputType(schemaType string, allowedValues []JiraMetadataIssueFieldOption) string {
	switch strings.ToLower(strings.TrimSpace(schemaType)) {
	case "number", "integer":
		return "number"
	case "boolean":
		return "boolean"
	case "array":
		if len(allowedValues) > 0 {
			return "multi_select"
		}
		return "text"
	default:
		if len(allowedValues) > 0 {
			return "single_select"
		}
		return "text"
	}
}

func parseJiraIssueFieldAllowedValues(raw []any) []JiraMetadataIssueFieldOption {
	if len(raw) == 0 {
		return nil
	}
	out := make([]JiraMetadataIssueFieldOption, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		option := JiraMetadataIssueFieldOption{
			ID:    strings.TrimSpace(fmt.Sprintf("%v", m["id"])),
			Name:  strings.TrimSpace(fmt.Sprintf("%v", m["name"])),
			Value: strings.TrimSpace(fmt.Sprintf("%v", m["value"])),
		}
		if option.ID == "<nil>" {
			option.ID = ""
		}
		if option.Name == "<nil>" {
			option.Name = ""
		}
		if option.Value == "<nil>" {
			option.Value = ""
		}
		if option.ID == "" && option.Name == "" && option.Value == "" {
			continue
		}
		key := option.ID + "|" + option.Name + "|" + option.Value
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, option)
	}
	return out
}

func JiraListRequiredIssueFields(ctx context.Context, cfg *JiraConnectorProfile, projectKey, issueTypeID string) ([]JiraMetadataIssueField, error) {
	projectKey = strings.TrimSpace(projectKey)
	issueTypeID = strings.TrimSpace(issueTypeID)
	if projectKey == "" {
		return nil, errors.New("jira project key is required")
	}
	if issueTypeID == "" {
		return nil, errors.New("jira issue type id is required")
	}

	qProject := url.QueryEscape(projectKey)
	qIssueTypeID := url.QueryEscape(issueTypeID)
	pathTemplate := fmt.Sprintf(
		"/rest/api/%%d/issue/createmeta?projectKeys=%s&issuetypeIds=%s&expand=projects.issuetypes.fields",
		qProject,
		qIssueTypeID,
	)
	respBody, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodGet,
		pathTemplate,
		nil,
		http.StatusOK,
	)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Projects []struct {
			Key        string `json:"key"`
			IssueTypes []struct {
				ID     string `json:"id"`
				Name   string `json:"name"`
				Fields map[string]struct {
					Required      bool   `json:"required"`
					Name          string `json:"name"`
					AllowedValues []any  `json:"allowedValues"`
					Schema        struct {
						Type  string `json:"type"`
						Items string `json:"items"`
					} `json:"schema"`
				} `json:"fields"`
			} `json:"issuetypes"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}

	reserved := map[string]struct{}{
		"project":     {},
		"issuetype":   {},
		"summary":     {},
		"description": {},
		"priority":    {},
		"labels":      {},
		"components":  {},
	}
	out := make([]JiraMetadataIssueField, 0, 16)
	seen := make(map[string]struct{}, 16)
	for _, project := range parsed.Projects {
		if !strings.EqualFold(strings.TrimSpace(project.Key), projectKey) {
			continue
		}
		for _, issueType := range project.IssueTypes {
			if strings.TrimSpace(issueType.ID) != issueTypeID {
				continue
			}
			for rawKey, meta := range issueType.Fields {
				key := strings.TrimSpace(rawKey)
				if key == "" {
					continue
				}
				if _, blocked := reserved[strings.ToLower(key)]; blocked {
					continue
				}
				if !meta.Required {
					continue
				}
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				allowedValues := parseJiraIssueFieldAllowedValues(meta.AllowedValues)
				inputType := classifyJiraIssueFieldInputType(meta.Schema.Type, allowedValues)
				out = append(out, JiraMetadataIssueField{
					Key:           key,
					Name:          strings.TrimSpace(meta.Name),
					Required:      meta.Required,
					InputType:     inputType,
					AllowedValues: allowedValues,
				})
			}
		}
	}
	return out, nil
}

func ParseHTTPStatusCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var statusErr HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode, true
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return 0, false
	}
	if strings.HasPrefix(msg, "jira authentication failed (") {
		rest := strings.TrimPrefix(msg, "jira authentication failed (")
		closeIdx := strings.Index(rest, ")")
		if closeIdx > 0 {
			raw := strings.TrimSpace(rest[:closeIdx])
			parsed, parseErr := strconv.Atoi(raw)
			if parseErr == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func IsJiraAuthScopeMismatch(err error) bool {
	if err == nil {
		return false
	}
	var statusErr HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	if statusErr.StatusCode != http.StatusUnauthorized {
		return false
	}
	return jiraScopeMismatchBody([]byte(statusErr.Body))
}
