package handlers

import (
	"errors"
	"net/http"
	"strings"

	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/core/auth"
	"backend/internal/eventmeta"
	"backend/internal/store"

	"github.com/google/uuid"
)

type jiraEntitySettingsRequest struct {
	IsEnabled                   bool              `json:"isEnabled"`
	JiraProjectKey              string            `json:"jiraProjectKey"`
	IssueType                   string            `json:"issueType"`
	DeliveryRetryAttempts       *int              `json:"deliveryRetryAttempts,omitempty"`
	DeliveryRetryBackoffSeconds *int              `json:"deliveryRetryBackoffSeconds,omitempty"`
	OpenTransitionName          string            `json:"openTransitionName"`
	ResolveTransitionName       string            `json:"resolveTransitionName"`
	IssueFields                 map[string]any    `json:"issueFields"`
	Labels                      []string          `json:"labels"`
	Components                  []string          `json:"components"`
	SeverityToPriorityMapping   map[string]string `json:"severityToPriorityMapping"`
	TicketSummaryTemplate       string            `json:"ticketSummaryTemplate"`
}

func defaultJiraSettings(projectID uuid.UUID, level store.JiraConfigLevel, targetID uuid.UUID) *store.JiraEntitySettings {
	return &store.JiraEntitySettings{
		ID:                          uuid.Nil,
		ProjectID:                   projectID,
		ConfigLevel:                 level,
		ConfigTargetID:              targetID,
		IsEnabled:                   false,
		JiraProjectKey:              "",
		IssueType:                   "",
		DeliveryRetryAttempts:       store.JiraDeliveryRetryAttemptsDefault,
		DeliveryRetryBackoffSeconds: store.JiraDeliveryRetryBackoffSecondsDefault,
		OpenTransitionName:          "",
		ResolveTransitionName:       "",
		IssueFields:                 map[string]any{},
		Labels:                      []string{},
		Components:                  []string{},
		SeverityToPriorityMapping:   map[string]string{},
		TicketSummaryTemplate:       "",
	}
}

func normalizeJiraSettingsRequest(req jiraEntitySettingsRequest) jiraEntitySettingsRequest {
	req.JiraProjectKey = sanitizePlainText(req.JiraProjectKey)
	req.IssueType = sanitizePlainText(req.IssueType)
	req.OpenTransitionName = sanitizePlainText(req.OpenTransitionName)
	req.ResolveTransitionName = sanitizePlainText(req.ResolveTransitionName)
	req.TicketSummaryTemplate = sanitizePlainText(req.TicketSummaryTemplate)
	if req.DeliveryRetryAttempts == nil {
		defaultValue := store.JiraDeliveryRetryAttemptsDefault
		req.DeliveryRetryAttempts = &defaultValue
	}
	if req.DeliveryRetryBackoffSeconds == nil {
		defaultValue := store.JiraDeliveryRetryBackoffSecondsDefault
		req.DeliveryRetryBackoffSeconds = &defaultValue
	}
	if req.IssueFields == nil {
		req.IssueFields = map[string]any{}
	} else {
		req.IssueFields = sanitizeJiraSettingsIssueFieldsMap(req.IssueFields)
	}
	if req.Labels == nil {
		req.Labels = []string{}
	} else {
		req.Labels = sanitizeJiraSettingsStringList(req.Labels)
	}
	if req.Components == nil {
		req.Components = []string{}
	} else {
		req.Components = sanitizeJiraSettingsStringList(req.Components)
	}
	if req.SeverityToPriorityMapping == nil {
		req.SeverityToPriorityMapping = map[string]string{}
	} else {
		req.SeverityToPriorityMapping = sanitizeJiraSettingsPriorityMapping(req.SeverityToPriorityMapping)
	}
	return req
}

func sanitizeJiraSettingsIssueFieldsValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		clean := sanitizePlainText(typed)
		if clean == "" {
			return nil, false
		}
		return clean, true
	case bool:
		return typed, true
	case float64:
		return typed, true
	case int:
		return typed, true
	case int32:
		return typed, true
	case int64:
		return typed, true
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			clean, ok := sanitizeJiraSettingsIssueFieldsValue(item)
			if !ok {
				continue
			}
			out = append(out, clean)
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case map[string]any:
		out := make(map[string]any, len(typed))
		for rawKey, item := range typed {
			cleanKey := sanitizePlainText(rawKey)
			if cleanKey == "" {
				continue
			}
			clean, ok := sanitizeJiraSettingsIssueFieldsValue(item)
			if !ok {
				continue
			}
			out[cleanKey] = clean
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

func sanitizeJiraSettingsIssueFieldsMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
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
	out := make(map[string]any, len(input))
	for rawKey, value := range input {
		cleanKey := sanitizePlainText(rawKey)
		if cleanKey == "" {
			continue
		}
		if _, blocked := reserved[strings.ToLower(cleanKey)]; blocked {
			continue
		}
		clean, ok := sanitizeJiraSettingsIssueFieldsValue(value)
		if !ok {
			continue
		}
		out[cleanKey] = clean
	}
	return out
}

func sanitizeJiraSettingsStringList(values []string) []string {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		clean := sanitizePlainText(value)
		if clean == "" {
			continue
		}
		if _, exists := seen[clean]; exists {
			continue
		}
		seen[clean] = struct{}{}
		normalized = append(normalized, clean)
	}
	return normalized
}

func sanitizeJiraSettingsPriorityMapping(input map[string]string) map[string]string {
	normalized := make(map[string]string, len(input))
	for key, value := range input {
		cleanKey := strings.ToUpper(sanitizePlainText(key))
		cleanValue := sanitizePlainText(value)
		if cleanKey == "" || cleanValue == "" {
			continue
		}
		normalized[cleanKey] = cleanValue
	}
	return normalized
}

func validateJiraSettingsRequest(req jiraEntitySettingsRequest) error {
	if req.DeliveryRetryAttempts == nil || *req.DeliveryRetryAttempts < store.JiraDeliveryRetryAttemptsMin || *req.DeliveryRetryAttempts > store.JiraDeliveryRetryAttemptsMax {
		return store.ErrInvalidPayload
	}
	if req.DeliveryRetryBackoffSeconds == nil || *req.DeliveryRetryBackoffSeconds < store.JiraDeliveryRetryBackoffSecondsMin || *req.DeliveryRetryBackoffSeconds > store.JiraDeliveryRetryBackoffSecondsMax {
		return store.ErrInvalidPayload
	}
	if !req.IsEnabled {
		return nil
	}
	if req.JiraProjectKey == "" {
		return store.ErrInvalidPayload
	}
	if req.IssueType == "" {
		return store.ErrInvalidPayload
	}
	if req.TicketSummaryTemplate == "" {
		return store.ErrInvalidPayload
	}
	return nil
}

func requireProductOwnerForJiraSettings(st store.Store, projectID, productID uuid.UUID, userCtx auth.UserContext) *resolveError {
	if userCtx.Role == auth.RoleAdmin {
		return nil
	}
	projectRole, err := st.GetProjectRole(userCtx.ID, projectID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve project role.",
			err:    err,
		}
	}
	if err == nil && store.ProjectRoleAtLeast(projectRole, store.ProjectRoleAdmin) {
		return nil
	}

	role, err := st.GetEffectiveProductRole(projectID, productID, userCtx.ID)
	if err == store.ErrNotFound {
		return &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Product not found.",
		}
	}
	if err != nil {
		return &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to resolve product ownership.",
			err:    err,
		}
	}
	if strings.ToUpper(strings.TrimSpace(role)) != store.GroupMemberRoleOwner {
		return &resolveError{
			status: http.StatusForbidden,
			title:  "Forbidden",
			detail: "Product owner role required.",
		}
	}
	return nil
}

func getProductJiraTarget(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
	productID, err := uuid.Parse(strings.TrimSpace(r.PathValue("productId")))
	if err != nil {
		return uuid.Nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Invalid productId.",
			err:    err,
		}
	}
	if _, err := st.GetProductInProject(projectID, productID); err == store.ErrNotFound {
		return uuid.Nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Product not found.",
		}
	} else if err != nil {
		return uuid.Nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load product.",
			err:    err,
		}
	}
	return productID, nil
}

func getScopeJiraTarget(r *http.Request, st store.Store, projectID uuid.UUID) (scopeID uuid.UUID, productID uuid.UUID, resolveErr *resolveError) {
	scopeID, err := uuid.Parse(strings.TrimSpace(r.PathValue("scopeId")))
	if err != nil {
		return uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Invalid scopeId.",
			err:    err,
		}
	}
	scope, err := st.GetScopeInProject(projectID, scopeID)
	if err == store.ErrNotFound {
		return uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Scope not found.",
		}
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load scope.",
			err:    err,
		}
	}
	return scopeID, scope.ProductID, nil
}

func getTestJiraTarget(r *http.Request, st store.Store, projectID uuid.UUID) (testID uuid.UUID, scopeID uuid.UUID, productID uuid.UUID, resolveErr *resolveError) {
	testID, err := uuid.Parse(strings.TrimSpace(r.PathValue("testId")))
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusBadRequest,
			title:  "Invalid Request",
			detail: "Invalid testId.",
			err:    err,
		}
	}
	testEntity, err := st.GetTestInProject(projectID, testID)
	if err == store.ErrNotFound {
		return uuid.Nil, uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Test not found.",
		}
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load test.",
			err:    err,
		}
	}
	scope, err := st.GetScopeInProject(projectID, testEntity.ScopeID)
	if err == store.ErrNotFound {
		return uuid.Nil, uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusNotFound,
			title:  "Not Found",
			detail: "Scope not found.",
		}
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, uuid.Nil, &resolveError{
			status: http.StatusInternalServerError,
			title:  "Internal Error",
			detail: "Failed to load scope.",
			err:    err,
		}
	}
	return testID, testEntity.ScopeID, scope.ProductID, nil
}

func getJiraSettingsByTargetHandler(st store.Store, level store.JiraConfigLevel, resolveTarget func(*http.Request, store.Store, uuid.UUID) (uuid.UUID, *resolveError)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		targetID, targetErr := resolveTarget(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}

		item, err := st.GetJiraEntitySettings(project.ID, level, targetID)
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, defaultJiraSettings(project.ID, level, targetID))
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to load Jira settings.", err)
			return
		}
		writeJSON(w, http.StatusOK, item)
	}
}

func putJiraSettingsByTargetHandler(
	st store.Store,
	auditWriter *audit.Writer,
	level store.JiraConfigLevel,
	resolveTargetAndOwner func(*http.Request, store.Store, uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userCtx, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		targetID, productID, targetErr := resolveTargetAndOwner(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}
		if authzErr := requireProductOwnerForJiraSettings(st, project.ID, productID, userCtx); authzErr != nil {
			writeProblem(w, r, authzErr.status, authzErr.title, authzErr.detail, authzErr.err)
			return
		}

		var req jiraEntitySettingsRequest
		if err := decodeJSON(r, &req); err != nil {
			writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid JSON body.", err)
			return
		}
		req = normalizeJiraSettingsRequest(req)
		if err := validateJiraSettingsRequest(req); err != nil {
			writeProblem(
				w,
				r,
				http.StatusBadRequest,
				"Invalid Request",
				"Invalid Jira settings payload. Enabled Jira settings require jiraProjectKey/issueType/ticketSummaryTemplate and retry values within allowed range.",
				err,
			)
			return
		}

		item, err := st.UpsertJiraEntitySettings(store.JiraEntitySettingsUpsertInput{
			ProjectID:                   project.ID,
			ConfigLevel:                 level,
			ConfigTargetID:              targetID,
			IsEnabled:                   req.IsEnabled,
			JiraProjectKey:              req.JiraProjectKey,
			IssueType:                   req.IssueType,
			DeliveryRetryAttempts:       *req.DeliveryRetryAttempts,
			DeliveryRetryBackoffSeconds: *req.DeliveryRetryBackoffSeconds,
			OpenTransitionName:          req.OpenTransitionName,
			ResolveTransitionName:       req.ResolveTransitionName,
			IssueFields:                 req.IssueFields,
			Labels:                      req.Labels,
			Components:                  req.Components,
			SeverityToPriorityMapping:   req.SeverityToPriorityMapping,
			TicketSummaryTemplate:       req.TicketSummaryTemplate,
		})
		if err != nil {
			if errors.Is(err, store.ErrInvalidPayload) {
				writeProblem(w, r, http.StatusBadRequest, "Invalid Request", "Invalid Jira settings payload.", err)
				return
			}
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to save Jira settings.", err)
			return
		}

		if auditWriter != nil {
			details, detailsErr := audit.BuildDetails(audit.DetailsBase{
				Category:  eventmeta.CategoryConfig,
				Severity:  eventmeta.SeverityInfo,
				MinRole:   eventmeta.MinRoleWrite,
				EventKey:  "config.jira_entity_settings_update",
				ProjectID: project.ID.String(),
				TraceID:   middleware.TraceIDFromContext(r.Context()),
				Title:     "Jira entity settings updated",
				Message:   "Product owner updated Jira settings on data entity.",
				Component: middleware.ComponentFromContext(r.Context()),
			}, map[string]any{
				"configLevel":    string(level),
				"configTargetId": targetID.String(),
				"isEnabled":      item.IsEnabled,
			})
			if detailsErr == nil {
				auditWriter.Write(store.AuditLogEntry{
					ActorID:    &userCtx.ID,
					Action:     "JIRA_ENTITY_SETTINGS_UPSERT",
					EntityType: "JIRA_SETTINGS",
					EntityID:   &targetID,
					Details:    details,
					IPAddress:  audit.IPFromRequest(r),
				}, true)
			}
		}

		writeJSON(w, http.StatusOK, item)
	}
}

func GetProductJiraSettingsHandler(st store.Store) http.HandlerFunc {
	return getJiraSettingsByTargetHandler(st, store.JiraConfigLevelProduct, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		productID, resolveErr := getProductJiraTarget(r, st, projectID)
		return productID, resolveErr
	})
}

func PutProductJiraSettingsHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return putJiraSettingsByTargetHandler(st, auditWriter, store.JiraConfigLevelProduct, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		productID, resolveErr := getProductJiraTarget(r, st, projectID)
		return productID, productID, resolveErr
	})
}

func GetScopeJiraSettingsHandler(st store.Store) http.HandlerFunc {
	return getJiraSettingsByTargetHandler(st, store.JiraConfigLevelScope, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		scopeID, _, resolveErr := getScopeJiraTarget(r, st, projectID)
		return scopeID, resolveErr
	})
}

func PutScopeJiraSettingsHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return putJiraSettingsByTargetHandler(st, auditWriter, store.JiraConfigLevelScope, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		scopeID, productID, resolveErr := getScopeJiraTarget(r, st, projectID)
		return scopeID, productID, resolveErr
	})
}

func GetTestJiraSettingsHandler(st store.Store) http.HandlerFunc {
	return getJiraSettingsByTargetHandler(st, store.JiraConfigLevelTest, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, *resolveError) {
		testID, _, _, resolveErr := getTestJiraTarget(r, st, projectID)
		return testID, resolveErr
	})
}

func PutTestJiraSettingsHandler(st store.Store, auditWriter *audit.Writer) http.HandlerFunc {
	return putJiraSettingsByTargetHandler(st, auditWriter, store.JiraConfigLevelTest, func(r *http.Request, st store.Store, projectID uuid.UUID) (uuid.UUID, uuid.UUID, *resolveError) {
		testID, _, productID, resolveErr := getTestJiraTarget(r, st, projectID)
		return testID, productID, resolveErr
	})
}

func GetTestEffectiveJiraSettingsHandler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, project, resolveErr := resolveActiveProject(r, st)
		if resolveErr != nil {
			writeProblem(w, r, resolveErr.status, resolveErr.title, resolveErr.detail, resolveErr.err)
			return
		}
		testID, scopeID, productID, targetErr := getTestJiraTarget(r, st, project.ID)
		if targetErr != nil {
			writeProblem(w, r, targetErr.status, targetErr.title, targetErr.detail, targetErr.err)
			return
		}

		effective, err := st.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
			ProjectID: project.ID,
			ProductID: &productID,
			ScopeID:   &scopeID,
			TestID:    &testID,
		})
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, r, http.StatusNotFound, "Not Found", "No effective Jira settings for this test.", nil)
			return
		}
		if err != nil {
			writeProblem(w, r, http.StatusInternalServerError, "Internal Error", "Failed to resolve effective Jira settings.", err)
			return
		}
		writeJSON(w, http.StatusOK, effective)
	}
}
