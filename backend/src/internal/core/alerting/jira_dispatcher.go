package alerting

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

func alertSeverityRank(raw string) int {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ERROR":
		return 3
	case "WARN", "WARNING":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func normalizeJiraMinSeverity(raw string) store.AlertMinSeverity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "ERROR":
		return store.AlertMinSeverityError
	case "WARN", "WARNING":
		return store.AlertMinSeverityWarning
	case "INFO":
		return store.AlertMinSeverityInfo
	default:
		return ""
	}
}

func jiraMeetsMinSeverity(groupSeverity string, minSeverity store.AlertMinSeverity) bool {
	threshold := minSeverity
	if threshold == "" {
		threshold = store.AlertMinSeverityInfo
	}
	return alertSeverityRank(groupSeverity) >= alertSeverityRank(string(threshold))
}

func resolveJiraConnectorSettings(st store.Store, projectID uuid.UUID) (*store.AlertConnectorSettings, error) {
	settings, err := st.GetAlertConnectorSettings(projectID)
	if err != nil {
		return nil, err
	}
	for _, item := range settings {
		if item.ConnectorType != store.ConnectorTypeJira {
			continue
		}
		setting := item
		return &setting, nil
	}
	return nil, store.ErrNotFound
}

func resolveJiraDispatchDedupPolicy(
	st store.Store,
	projectID uuid.UUID,
	group *models.AlertGroup,
	occCtx *store.AlertOccurrenceContext,
	jiraSettings *store.AlertConnectorSettings,
) (*uuid.UUID, store.AlertMinSeverity, error) {
	if st == nil || group == nil {
		return nil, store.AlertMinSeverityInfo, nil
	}

	// Explicit connector binding has priority.
	if jiraSettings != nil && jiraSettings.JiraDedupRuleID != nil && *jiraSettings.JiraDedupRuleID != uuid.Nil {
		rule, err := st.GetAlertDedupRuleByID(projectID, *jiraSettings.JiraDedupRuleID)
		if err != nil {
			return nil, "", err
		}
		if rule == nil || !rule.Enabled || !strings.EqualFold(strings.TrimSpace(rule.AlertType), strings.TrimSpace(group.Type)) {
			return nil, "", store.ErrInvalidPayload
		}
		min := normalizeJiraMinSeverity(rule.MinSeverity)
		if min == "" {
			min = store.AlertMinSeverityInfo
		}
		id := rule.ID
		return &id, min, nil
	}

	rule, err := st.ResolveAlertDedupRule(store.AlertDedupRuleResolutionInput{
		ProjectID: projectID,
		AlertType: strings.TrimSpace(group.Type),
		ProductID: occCtx.ProductID,
		ScopeID:   occCtx.ScopeID,
		TestID:    occCtx.TestID,
	})
	if err != nil {
		return nil, "", err
	}
	if rule == nil {
		return nil, store.AlertMinSeverityInfo, nil
	}
	min := normalizeJiraMinSeverity(rule.MinSeverity)
	if min == "" {
		min = store.AlertMinSeverityInfo
	}
	if rule.ID == uuid.Nil {
		return nil, min, nil
	}
	id := rule.ID
	return &id, min, nil
}

type jiraEntityNames struct {
	project string
	product string
	scope   string
	test    string
}

func loadJiraEntityNames(st store.Store, projectID uuid.UUID, occCtx *store.AlertOccurrenceContext) jiraEntityNames {
	resolved := loadAlertEntityNames(st, projectID, occCtx)
	return jiraEntityNames{
		project: resolved.project,
		product: resolved.product,
		scope:   resolved.scope,
		test:    resolved.test,
	}
}

func defaultSummaryTemplate(level store.JiraConfigLevel) string {
	switch level {
	case store.JiraConfigLevelTest:
		return "{{product}} / {{scope}} / {{test}} malware finding"
	case store.JiraConfigLevelScope:
		return "{{product}} / {{scope}} malware finding"
	default:
		return "{{product}} malware finding"
	}
}

func renderJiraSummary(template string, level store.JiraConfigLevel, group *models.AlertGroup, names jiraEntityNames) string {
	template = strings.TrimSpace(template)
	if template == "" {
		template = defaultSummaryTemplate(level)
	}
	severity := strings.ToUpper(strings.TrimSpace(string(group.Severity)))
	if severity == "" {
		severity = "INFO"
	}
	alertType := strings.TrimSpace(group.Type)
	if alertType == "" {
		alertType = "malware.detected"
	}
	componentToken := ""
	if group.EntityRef != nil {
		componentToken = strings.TrimSpace(*group.EntityRef)
	}

	replacements := map[string]string{
		"{{project}}":        names.project,
		"{{product}}":        names.product,
		"{{scope}}":          names.scope,
		"{{test}}":           names.test,
		"{{component_purl}}": componentToken,
		"{{severity}}":       severity,
		"{{finding_count}}":  fmt.Sprintf("%d", group.Occurrences),
		"{{dedup_key}}":      strings.TrimSpace(group.GroupKey),
		"{{alert_type}}":     alertType,
	}
	out := template
	for key, value := range replacements {
		out = strings.ReplaceAll(out, key, strings.TrimSpace(value))
	}
	out = strings.TrimSpace(out)
	if out == "" {
		out = "CTWall alert"
	}
	if len(out) > 255 {
		out = out[:252] + "..."
	}
	return out
}

func buildJiraDescription(group *models.AlertGroup, names jiraEntityNames, componentPURL string) string {
	lines := []string{
		"CTWall finding snapshot",
		"",
		"Title: " + strings.TrimSpace(group.Title),
		"Severity: " + strings.ToUpper(strings.TrimSpace(string(group.Severity))),
		"Status: " + strings.TrimSpace(string(group.Status)),
		"Occurrences: " + fmt.Sprintf("%d", group.Occurrences),
		"Alert type: " + strings.TrimSpace(group.Type),
		"Group key: " + strings.TrimSpace(group.GroupKey),
		"Project: " + names.project,
	}
	if names.product != "" {
		lines = append(lines, "Product: "+names.product)
	}
	if names.scope != "" {
		lines = append(lines, "Scope: "+names.scope)
	}
	if names.test != "" {
		lines = append(lines, "Test: "+names.test)
	}
	if strings.TrimSpace(componentPURL) != "" {
		lines = append(lines, "Component PURL: "+strings.TrimSpace(componentPURL))
	}
	if group.EntityRef != nil && strings.TrimSpace(*group.EntityRef) != "" {
		lines = append(lines, "Entity: "+strings.TrimSpace(*group.EntityRef))
	}
	return strings.Join(lines, "\n")
}

func cloneIssueFieldsMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func defaultEpicSummaryTemplate(level store.JiraConfigLevel) string {
	switch level {
	case store.JiraConfigLevelTest:
		return "CTWall Epic {{product}} / {{scope}} / {{test}}"
	case store.JiraConfigLevelScope:
		return "CTWall Epic {{product}} / {{scope}}"
	default:
		return "CTWall Epic {{product}}"
	}
}

func buildJiraEpicDescription(group *models.AlertGroup, names jiraEntityNames) string {
	lines := []string{
		"CTWall generated Epic for malware findings.",
		"",
		"Project: " + names.project,
	}
	if names.product != "" {
		lines = append(lines, "Product: "+names.product)
	}
	if names.scope != "" {
		lines = append(lines, "Scope: "+names.scope)
	}
	if names.test != "" {
		lines = append(lines, "Test: "+names.test)
	}
	lines = append(lines,
		"Severity: "+strings.ToUpper(strings.TrimSpace(string(group.Severity))),
		"Alert type: "+strings.TrimSpace(group.Type),
		"Group key: "+strings.TrimSpace(group.GroupKey),
	)
	return strings.Join(lines, "\n")
}

func ensureJiraEpicKeyForDispatch(
	ctx context.Context,
	st store.Store,
	projectID uuid.UUID,
	cfg *JiraConnectorProfile,
	level store.JiraConfigLevel,
	targetID uuid.UUID,
	settings store.JiraEntitySettings,
	group *models.AlertGroup,
	names jiraEntityNames,
	priorityName string,
) (map[string]any, error) {
	issueFields := cloneIssueFieldsMap(settings.IssueFields)
	epicCfg := parseJiraEpicConfig(issueFields)
	if epicCfg.Mode != jiraEpicModeCreate || epicCfg.IssueKey != "" {
		return issueFields, nil
	}

	epicSummaryTemplate := strings.TrimSpace(epicCfg.CreateSummary)
	if epicSummaryTemplate == "" {
		epicSummaryTemplate = defaultEpicSummaryTemplate(level)
	}
	epicIssueType := strings.TrimSpace(epicCfg.CreateIssueType)
	if epicIssueType == "" {
		epicIssueType = "Epic"
	}
	epicPayload := JiraIssueUpsertPayload{
		ProjectKey:   settings.JiraProjectKey,
		IssueType:    epicIssueType,
		Summary:      renderJiraSummary(epicSummaryTemplate, level, group, names),
		Description:  buildJiraEpicDescription(group, names),
		Labels:       settings.Labels,
		Components:   settings.Components,
		PriorityName: priorityName,
		IssueFields:  map[string]any{},
	}
	ref, err := JiraCreateIssue(ctx, cfg, epicPayload)
	if err != nil {
		return nil, fmt.Errorf("create jira epic: %w", err)
	}
	epicKey := strings.TrimSpace(ref.Key)
	if epicKey == "" {
		epicKey = strings.TrimSpace(ref.ID)
	}
	if epicKey == "" {
		return nil, errors.New("jira epic create response missing key/id")
	}

	issueFields[jiraEpicIssueKeyField] = epicKey
	issueFields[jiraEpicModeField] = string(jiraEpicModeCreate)

	_, upsertErr := st.UpsertJiraEntitySettings(store.JiraEntitySettingsUpsertInput{
		ProjectID:                   settings.ProjectID,
		ConfigLevel:                 settings.ConfigLevel,
		ConfigTargetID:              settings.ConfigTargetID,
		IsEnabled:                   settings.IsEnabled,
		JiraProjectKey:              settings.JiraProjectKey,
		IssueType:                   settings.IssueType,
		DeliveryRetryAttempts:       settings.DeliveryRetryAttempts,
		DeliveryRetryBackoffSeconds: settings.DeliveryRetryBackoffSeconds,
		OpenTransitionName:          settings.OpenTransitionName,
		ResolveTransitionName:       settings.ResolveTransitionName,
		IssueFields:                 issueFields,
		Labels:                      settings.Labels,
		Components:                  settings.Components,
		SeverityToPriorityMapping:   settings.SeverityToPriorityMapping,
		TicketSummaryTemplate:       settings.TicketSummaryTemplate,
	})
	if upsertErr != nil {
		slog.Warn("jira epic key persistence failed",
			"project_id", projectID.String(),
			"config_level", string(level),
			"config_target_id", targetID.String(),
			"epic_key", epicKey,
			"error", upsertErr,
		)
	}

	emitJiraSyncEvent(st, projectID, nil, "alerting.jira.epic_create", eventmeta.SeverityInfo, "Jira epic created", "Created Jira epic for automatic issue linking.", map[string]any{
		"configLevel":    string(level),
		"configTargetId": targetID.String(),
		"jiraEpicKey":    epicKey,
		"jiraEpicId":     strings.TrimSpace(ref.ID),
	})
	return issueFields, nil
}

func jiraPriorityForSeverity(mapping map[string]string, severity string) string {
	if len(mapping) == 0 {
		return ""
	}
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	if normalized == "WARN" {
		normalized = "WARNING"
	}
	if value, ok := mapping[normalized]; ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func jiraIssueIDOrKey(mapping store.JiraIssueMapping) string {
	if key := strings.TrimSpace(mapping.JiraIssueKey); key != "" {
		return key
	}
	return strings.TrimSpace(mapping.JiraIssueID)
}

func jiraAttemptStatus(err error) *int {
	if code, ok := ParseHTTPStatusCode(err); ok {
		return &code
	}
	return nil
}

func jiraIssueInaccessible(err error) bool {
	if err == nil {
		return false
	}
	code, ok := ParseHTTPStatusCode(err)
	if !ok {
		return false
	}
	return code == http.StatusNotFound || code == http.StatusForbidden
}

func validateJiraDispatchSettings(
	ctx context.Context,
	st store.Store,
	projectID uuid.UUID,
	cfg *JiraConnectorProfile,
	settings store.JiraEntitySettings,
) error {
	projectKey := strings.TrimSpace(settings.JiraProjectKey)
	issueType := strings.TrimSpace(settings.IssueType)
	if projectKey == "" {
		return errors.New("jiraProjectKey is required in effective Jira settings")
	}
	if issueType == "" {
		return errors.New("issueType is required in effective Jira settings")
	}
	issueTypes, _, err := LoadJiraIssueTypesWithCache(ctx, st, projectID, cfg, projectKey, false)
	if err != nil {
		return fmt.Errorf("jira project/issue type lookup failed for project %q: %w", projectKey, err)
	}
	for _, item := range issueTypes {
		if strings.EqualFold(strings.TrimSpace(item.Name), issueType) {
			return nil
		}
	}
	return fmt.Errorf("jira issueType %q is not available in project %q", issueType, projectKey)
}

func recordJiraAttempt(
	st store.Store,
	job store.AlertDispatchJob,
	action store.JiraDeliveryAction,
	outcome store.JiraDeliveryOutcome,
	projectID uuid.UUID,
	level *store.JiraConfigLevel,
	targetID *uuid.UUID,
	groupID *uuid.UUID,
	dedupRuleID *uuid.UUID,
	mappingID *uuid.UUID,
	err error,
) {
	var queueJobID *uuid.UUID
	if job.ID != uuid.Nil {
		queueJobID = &job.ID
	}
	input := store.JiraDeliveryAttemptInput{
		QueueJobID:         queueJobID,
		ProjectID:          projectID,
		ConfigLevel:        level,
		ConfigTargetID:     targetID,
		AlertGroupID:       groupID,
		DedupRuleID:        dedupRuleID,
		JiraIssueMappingID: mappingID,
		AttemptNo:          job.AttemptCount,
		Action:             action,
		Outcome:            outcome,
		HTTPStatus:         jiraAttemptStatus(err),
	}
	if err != nil {
		input.ErrorMessage = err.Error()
	}
	_ = st.InsertJiraDeliveryAttempt(input)
}

func emitJiraSyncEvent(
	st store.Store,
	projectID uuid.UUID,
	groupID *uuid.UUID,
	eventKey string,
	severity eventmeta.Severity,
	title string,
	message string,
	extra map[string]any,
) {
	if st == nil {
		return
	}
	details, err := audit.BuildDetails(audit.DetailsBase{
		Category:  eventmeta.CategorySystem,
		Severity:  severity,
		MinRole:   eventmeta.MinRoleWrite,
		EventKey:  strings.TrimSpace(eventKey),
		ProjectID: projectID.String(),
		Title:     strings.TrimSpace(title),
		Message:   strings.TrimSpace(message),
		Component: "core.alerting.jira_dispatcher",
	}, extra)
	if err != nil {
		return
	}
	_ = st.CreateAuditLog(store.AuditLogEntry{
		Action:     "JIRA_SYNC_EVENT",
		EntityType: "ALERT_GROUP",
		EntityID:   groupID,
		Details:    details,
	})
}

func applyJiraTransition(ctx context.Context, cfg *JiraConnectorProfile, issueIDOrKey, transitionID string) error {
	issueIDOrKey = strings.TrimSpace(issueIDOrKey)
	transitionID = strings.TrimSpace(transitionID)
	if issueIDOrKey == "" || transitionID == "" {
		return errors.New("jira transition requires issue and transition id")
	}
	_, _, err := jiraDoJSON(
		ctx,
		cfg,
		jiraHTTPClient(cfg.RequestTimeoutSeconds),
		http.MethodPost,
		"/rest/api/%d/issue/"+issueIDOrKey+"/transitions",
		map[string]any{
			"transition": map[string]string{
				"id": transitionID,
			},
		},
		http.StatusNoContent,
		http.StatusOK,
		http.StatusCreated,
	)
	return err
}

func isPotentialTransitionError(err error) bool {
	status, ok := ParseHTTPStatusCode(err)
	if !ok {
		return false
	}
	return status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusConflict
}

func resolveIssueWithTransitionCache(ctx context.Context, st store.Store, projectID uuid.UUID, cfg *JiraConnectorProfile, issueIDOrKey, transitionName string) error {
	issueIDOrKey = strings.TrimSpace(issueIDOrKey)
	if issueIDOrKey == "" {
		return errors.New("jira issue id/key is required")
	}

	transitions, fromCache, err := loadJiraTransitionsWithCache(ctx, st, projectID, cfg, issueIDOrKey, false)
	if err != nil {
		return err
	}
	transitionID := resolveTransitionIDByName(transitions, transitionName)
	if transitionID == "" {
		transitions, _, err = loadJiraTransitionsWithCache(ctx, st, projectID, cfg, issueIDOrKey, true)
		if err != nil {
			return err
		}
		transitionID = resolveTransitionIDByName(transitions, transitionName)
	}
	if transitionID == "" {
		if strings.TrimSpace(transitionName) == "" {
			return errors.New("jira close transition not found in workflow")
		}
		return fmt.Errorf("jira transition %q not found in workflow", strings.TrimSpace(transitionName))
	}

	err = applyJiraTransition(ctx, cfg, issueIDOrKey, transitionID)
	if err == nil {
		return nil
	}
	if fromCache || !isPotentialTransitionError(err) {
		return err
	}
	// Transition list might be stale, force-refresh once and retry.
	transitions, _, refreshErr := loadJiraTransitionsWithCache(ctx, st, projectID, cfg, issueIDOrKey, true)
	if refreshErr != nil {
		return refreshErr
	}
	transitionID = resolveTransitionIDByName(transitions, transitionName)
	if transitionID == "" {
		if strings.TrimSpace(transitionName) == "" {
			return errors.New("jira close transition not found in workflow")
		}
		return fmt.Errorf("jira transition %q not found in workflow", strings.TrimSpace(transitionName))
	}
	return applyJiraTransition(ctx, cfg, issueIDOrKey, transitionID)
}

func closeJiraMapping(
	ctx context.Context,
	st store.Store,
	job store.AlertDispatchJob,
	cfg *JiraConnectorProfile,
	mapping store.JiraIssueMapping,
	outcomeStatus store.JiraIssueMappingStatus,
	action store.JiraDeliveryAction,
) error {
	issueIDOrKey := jiraIssueIDOrKey(mapping)
	transitionName := ""
	if settings, err := st.GetJiraEntitySettings(mapping.ProjectID, mapping.ConfigLevel, mapping.ConfigTargetID); err == nil && settings != nil {
		transitionName = strings.TrimSpace(settings.ResolveTransitionName)
	}

	now := time.Now().UTC()
	if issueIDOrKey != "" {
		if err := resolveIssueWithTransitionCache(ctx, st, mapping.ProjectID, cfg, issueIDOrKey, transitionName); err != nil {
			level := mapping.ConfigLevel
			targetID := mapping.ConfigTargetID
			groupID := mapping.AlertGroupID
			recordJiraAttempt(st, job, action, store.JiraDeliveryOutcomeFailed, mapping.ProjectID, &level, &targetID, &groupID, mapping.DedupRuleID, &mapping.ID, err)
			message := "Failed to resolve Jira issue transition."
			if jiraIssueInaccessible(err) {
				message = "Failed to resolve Jira issue transition because the issue is inaccessible (404/403)."
			}
			emitJiraSyncEvent(st, mapping.ProjectID, &mapping.AlertGroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", message, map[string]any{
				"configLevel":    string(mapping.ConfigLevel),
				"configTargetId": mapping.ConfigTargetID.String(),
				"alertGroupId":   mapping.AlertGroupID.String(),
				"jiraIssueKey":   mapping.JiraIssueKey,
				"jiraIssueId":    mapping.JiraIssueID,
				"error":          err.Error(),
			})
			return err
		}

		statusSnapshot, statusErr := JiraGetIssueStatusSnapshot(ctx, cfg, issueIDOrKey)
		if statusErr != nil {
			level := mapping.ConfigLevel
			targetID := mapping.ConfigTargetID
			groupID := mapping.AlertGroupID
			recordJiraAttempt(st, job, action, store.JiraDeliveryOutcomeFailed, mapping.ProjectID, &level, &targetID, &groupID, mapping.DedupRuleID, &mapping.ID, statusErr)
			emitJiraSyncEvent(st, mapping.ProjectID, &mapping.AlertGroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Failed to verify Jira issue state after resolve transition.", map[string]any{
				"configLevel":    string(mapping.ConfigLevel),
				"configTargetId": mapping.ConfigTargetID.String(),
				"alertGroupId":   mapping.AlertGroupID.String(),
				"jiraIssueKey":   mapping.JiraIssueKey,
				"jiraIssueId":    mapping.JiraIssueID,
				"error":          statusErr.Error(),
			})
			return statusErr
		}
		if !jiraIssueIsClosed(statusSnapshot) {
			verifyErr := fmt.Errorf(
				"jira issue was not closed after resolve transition: status=%q statusCategory=%q resolution=%q",
				strings.TrimSpace(statusSnapshot.StatusName),
				strings.TrimSpace(statusSnapshot.StatusCategoryKey),
				strings.TrimSpace(statusSnapshot.ResolutionName),
			)
			level := mapping.ConfigLevel
			targetID := mapping.ConfigTargetID
			groupID := mapping.AlertGroupID
			recordJiraAttempt(st, job, action, store.JiraDeliveryOutcomeFailed, mapping.ProjectID, &level, &targetID, &groupID, mapping.DedupRuleID, &mapping.ID, verifyErr)
			emitJiraSyncEvent(st, mapping.ProjectID, &mapping.AlertGroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Resolve transition executed but Jira issue is still open.", map[string]any{
				"configLevel":        string(mapping.ConfigLevel),
				"configTargetId":     mapping.ConfigTargetID.String(),
				"alertGroupId":       mapping.AlertGroupID.String(),
				"jiraIssueKey":       mapping.JiraIssueKey,
				"jiraIssueId":        mapping.JiraIssueID,
				"jiraStatus":         strings.TrimSpace(statusSnapshot.StatusName),
				"jiraStatusCategory": strings.TrimSpace(statusSnapshot.StatusCategoryKey),
				"jiraResolution":     strings.TrimSpace(statusSnapshot.ResolutionName),
			})
			return verifyErr
		}
	}

	updated, err := st.UpsertJiraIssueMapping(store.JiraIssueMappingUpsertInput{
		ProjectID:               mapping.ProjectID,
		ConfigLevel:             mapping.ConfigLevel,
		ConfigTargetID:          mapping.ConfigTargetID,
		AlertGroupID:            mapping.AlertGroupID,
		DedupRuleID:             mapping.DedupRuleID,
		TestID:                  mapping.TestID,
		ComponentPURL:           mapping.ComponentPURL,
		EffectiveConfigLevel:    mapping.EffectiveConfigLevel,
		EffectiveConfigTargetID: mapping.EffectiveConfigTargetID,
		JiraIssueKey:            mapping.JiraIssueKey,
		JiraIssueID:             mapping.JiraIssueID,
		Status:                  outcomeStatus,
		LastSyncedAt:            &now,
		LastError:               "",
		ClosedAt:                &now,
	})
	if err != nil {
		level := mapping.ConfigLevel
		targetID := mapping.ConfigTargetID
		groupID := mapping.AlertGroupID
		recordJiraAttempt(st, job, action, store.JiraDeliveryOutcomeFailed, mapping.ProjectID, &level, &targetID, &groupID, mapping.DedupRuleID, &mapping.ID, err)
		return err
	}

	level := updated.ConfigLevel
	targetID := updated.ConfigTargetID
	groupID := updated.AlertGroupID
	recordJiraAttempt(st, job, action, store.JiraDeliveryOutcomeSuccess, mapping.ProjectID, &level, &targetID, &groupID, updated.DedupRuleID, &updated.ID, nil)
	emitJiraSyncEvent(st, mapping.ProjectID, &mapping.AlertGroupID, "alerting.jira.issue_resolve", eventmeta.SeverityInfo, "Jira issue resolved", "Correlated Jira issue was transitioned to resolved state.", map[string]any{
		"configLevel":    string(mapping.ConfigLevel),
		"configTargetId": mapping.ConfigTargetID.String(),
		"alertGroupId":   mapping.AlertGroupID.String(),
		"jiraIssueKey":   updated.JiraIssueKey,
		"jiraIssueId":    updated.JiraIssueID,
		"resolveAction":  string(action),
	})
	return nil
}

type jiraComponentContext struct {
	productID     uuid.UUID
	scopeID       uuid.UUID
	testID        uuid.UUID
	componentPURL string
}

func jiraComponentContextKey(testID uuid.UUID, componentPURL string) string {
	return testID.String() + "|" + strings.TrimSpace(componentPURL)
}

func mergeJiraComponentContext(target *jiraComponentContext, source jiraComponentContext) jiraComponentContext {
	out := jiraComponentContext{
		productID:     target.productID,
		scopeID:       target.scopeID,
		testID:        target.testID,
		componentPURL: target.componentPURL,
	}
	if out.productID == uuid.Nil && source.productID != uuid.Nil {
		out.productID = source.productID
	}
	if out.scopeID == uuid.Nil && source.scopeID != uuid.Nil {
		out.scopeID = source.scopeID
	}
	if out.testID == uuid.Nil && source.testID != uuid.Nil {
		out.testID = source.testID
	}
	if out.componentPURL == "" {
		out.componentPURL = source.componentPURL
	}
	return out
}

func processJiraAlertEventJob(
	ctx context.Context,
	st store.Store,
	job store.AlertDispatchJob,
	group *models.AlertGroup,
	eventState store.AlertDispatchEventState,
	logger *slog.Logger,
) error {
	if st == nil || group == nil || job.ProjectID == nil || job.GroupID == nil {
		return nil
	}

	projectConnector, err := st.GetProjectConnectorConfig(*job.ProjectID, store.ConnectorTypeJira)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if projectConnector == nil || !projectConnector.IsEnabled {
		return nil
	}
	cfg, err := ParseJiraConnectorProfile(projectConnector.ConfigJSON)
	if err != nil {
		return err
	}

	var occCtx *store.AlertOccurrenceContext
	occCtx, err = st.GetLatestAlertOccurrenceContext(*job.ProjectID, *job.GroupID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if errors.Is(err, store.ErrNotFound) {
		occCtx = nil
	}

	jiraConnectorSettings, err := resolveJiraConnectorSettings(st, *job.ProjectID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if errors.Is(err, store.ErrNotFound) {
		jiraConnectorSettings = nil
	}

	dedupRuleID, minSeverity, err := resolveJiraDispatchDedupPolicy(st, *job.ProjectID, group, occCtx, jiraConnectorSettings)
	if err != nil {
		return err
	}

	openMappings, err := st.ListOpenJiraIssueMappings(*job.ProjectID, *job.GroupID, nil)
	if err != nil {
		return err
	}

	if eventState == store.AlertDispatchEventStateFiring && !jiraMeetsMinSeverity(group.Severity, minSeverity) {
		if len(openMappings) == 0 {
			recordJiraAttempt(st, job, store.JiraDeliveryActionNoop, store.JiraDeliveryOutcomeSkipped, *job.ProjectID, nil, nil, job.GroupID, dedupRuleID, nil, nil)
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_succeeded", eventmeta.SeverityInfo, "Jira sync skipped", "Jira dispatch skipped by dedup minSeverity threshold.", map[string]any{
				"alertGroupId":  job.GroupID.String(),
				"groupSeverity": strings.ToUpper(strings.TrimSpace(group.Severity)),
				"minSeverity":   string(minSeverity),
			})
			return nil
		}
		for _, mapping := range openMappings {
			if err := closeJiraMapping(ctx, st, job, cfg, mapping, store.JiraIssueMappingStatusSuperseded, store.JiraDeliveryActionSupersedeClose); err != nil {
				return err
			}
		}
		emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_succeeded", eventmeta.SeverityInfo, "Jira sync succeeded", "Jira mappings closed due to dedup minSeverity threshold.", map[string]any{
			"alertGroupId":  job.GroupID.String(),
			"groupSeverity": strings.ToUpper(strings.TrimSpace(group.Severity)),
			"minSeverity":   string(minSeverity),
		})
		return nil
	}
	componentContexts, err := st.ListAlertGroupComponentContexts(*job.ProjectID, *job.GroupID)
	if err != nil {
		return err
	}
	componentCtxByKey := make(map[string]jiraComponentContext, len(componentContexts)+len(openMappings))
	for _, item := range componentContexts {
		contextItem := jiraComponentContext{
			productID:     item.ProductID,
			scopeID:       item.ScopeID,
			testID:        item.TestID,
			componentPURL: strings.TrimSpace(item.ComponentPURL),
		}
		if contextItem.testID == uuid.Nil || contextItem.componentPURL == "" {
			continue
		}
		key := jiraComponentContextKey(contextItem.testID, contextItem.componentPURL)
		existing, ok := componentCtxByKey[key]
		if !ok {
			componentCtxByKey[key] = contextItem
			continue
		}
		componentCtxByKey[key] = mergeJiraComponentContext(&existing, contextItem)
	}

	for _, mapping := range openMappings {
		if mapping.TestID == nil || *mapping.TestID == uuid.Nil || strings.TrimSpace(mapping.ComponentPURL) == "" {
			continue
		}
		contextItem := jiraComponentContext{
			testID:        *mapping.TestID,
			componentPURL: strings.TrimSpace(mapping.ComponentPURL),
		}
		key := jiraComponentContextKey(contextItem.testID, contextItem.componentPURL)
		existing, ok := componentCtxByKey[key]
		if !ok {
			componentCtxByKey[key] = contextItem
			continue
		}
		componentCtxByKey[key] = mergeJiraComponentContext(&existing, contextItem)
	}

	if len(componentCtxByKey) == 0 {
		recordJiraAttempt(st, job, store.JiraDeliveryActionNoop, store.JiraDeliveryOutcomeSkipped, *job.ProjectID, nil, nil, job.GroupID, dedupRuleID, nil, nil)
		return nil
	}

	testContextCache := make(map[uuid.UUID]jiraComponentContext, len(componentCtxByKey))
	reconciledCount := 0
	for key, item := range componentCtxByKey {
		if item.testID == uuid.Nil || item.componentPURL == "" {
			continue
		}
		if item.productID == uuid.Nil || item.scopeID == uuid.Nil {
			cached, ok := testContextCache[item.testID]
			if !ok {
				testEntity, getTestErr := st.GetTestInProject(*job.ProjectID, item.testID)
				if getTestErr != nil || testEntity == nil || testEntity.ScopeID == uuid.Nil {
					logger.Warn("jira lifecycle context missing test/scope for component", "project_id", *job.ProjectID, "group_id", *job.GroupID, "test_id", item.testID, "component_purl", item.componentPURL, "error", getTestErr)
					continue
				}
				scopeEntity, getScopeErr := st.GetScopeInProject(*job.ProjectID, testEntity.ScopeID)
				if getScopeErr != nil || scopeEntity == nil || scopeEntity.ProductID == uuid.Nil {
					logger.Warn("jira lifecycle context missing product for component", "project_id", *job.ProjectID, "group_id", *job.GroupID, "scope_id", testEntity.ScopeID, "component_purl", item.componentPURL, "error", getScopeErr)
					continue
				}
				cached = jiraComponentContext{
					productID: scopeEntity.ProductID,
					scopeID:   scopeEntity.ID,
					testID:    item.testID,
				}
				testContextCache[item.testID] = cached
			}
			item = mergeJiraComponentContext(&item, cached)
			componentCtxByKey[key] = item
		}

		active, activeErr := st.IsComponentMalwareActiveInTest(*job.ProjectID, item.testID, item.componentPURL)
		if activeErr != nil {
			return activeErr
		}

		mapping, mappingErr := st.GetLatestJiraIssueMappingForComponent(*job.ProjectID, item.testID, item.componentPURL)
		if mappingErr != nil && !errors.Is(mappingErr, store.ErrNotFound) {
			return mappingErr
		}
		if errors.Is(mappingErr, store.ErrNotFound) {
			mapping = nil
		}

		if !active {
			if mapping != nil && mapping.Status == store.JiraIssueMappingStatusOpen {
				if closeErr := closeJiraMapping(ctx, st, job, cfg, *mapping, store.JiraIssueMappingStatusClosed, store.JiraDeliveryActionResolve); closeErr != nil {
					return closeErr
				}
				reconciledCount++
				emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.issue_auto_close_component_clean", eventmeta.SeverityInfo, "Jira issue auto-closed", "Closed Jira issue because component has no active malware findings.", map[string]any{
					"componentPurl": item.componentPURL,
					"testId":        item.testID.String(),
					"jiraIssueKey":  mapping.JiraIssueKey,
					"jiraIssueId":   mapping.JiraIssueID,
				})
			}
			continue
		}

		productID := item.productID
		scopeID := item.scopeID
		testID := item.testID
		effective, effectiveErr := st.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
			ProjectID: *job.ProjectID,
			ProductID: &productID,
			ScopeID:   &scopeID,
			TestID:    &testID,
		})
		if effectiveErr != nil && !errors.Is(effectiveErr, store.ErrNotFound) {
			return effectiveErr
		}
		if errors.Is(effectiveErr, store.ErrNotFound) || effective == nil {
			if mapping != nil && mapping.Status == store.JiraIssueMappingStatusOpen {
				if closeErr := closeJiraMapping(ctx, st, job, cfg, *mapping, store.JiraIssueMappingStatusSuperseded, store.JiraDeliveryActionSupersedeClose); closeErr != nil {
					return closeErr
				}
				reconciledCount++
			}
			continue
		}

		if validationErr := validateJiraDispatchSettings(ctx, st, *job.ProjectID, cfg, effective.Settings); validationErr != nil {
			level := effective.ResolvedFromLevel
			targetID := effective.ResolvedTargetID
			var mappingID *uuid.UUID
			if mapping != nil {
				mappingID = &mapping.ID
			}
			recordJiraAttempt(st, job, store.JiraDeliveryActionNoop, store.JiraDeliveryOutcomeSkipped, *job.ProjectID, &level, &targetID, job.GroupID, dedupRuleID, mappingID, validationErr)
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_skipped", eventmeta.SeverityWarn, "Jira sync skipped", "Jira synchronization skipped due invalid Jira target settings.", map[string]any{
				"configLevel":    string(level),
				"configTargetId": targetID.String(),
				"alertGroupId":   job.GroupID.String(),
				"componentPurl":  item.componentPURL,
				"error":          validationErr.Error(),
			})
			continue
		}

		ownerLevel := effective.ResolvedFromLevel
		ownerTargetID := effective.ResolvedTargetID
		occCtxItem := &store.AlertOccurrenceContext{
			ProductID: &productID,
			ScopeID:   &scopeID,
			TestID:    &testID,
		}
		names := loadJiraEntityNames(st, *job.ProjectID, occCtxItem)
		summary := renderJiraSummary(effective.Settings.TicketSummaryTemplate, ownerLevel, group, names)
		description := buildJiraDescription(group, names, item.componentPURL)
		priority := jiraPriorityForSeverity(effective.Settings.SeverityToPriorityMapping, string(group.Severity))
		issueFields := cloneIssueFieldsMap(effective.Settings.IssueFields)
		issuePayload := JiraIssueUpsertPayload{
			ProjectKey:   effective.Settings.JiraProjectKey,
			IssueType:    effective.Settings.IssueType,
			Summary:      summary,
			Description:  description,
			Labels:       effective.Settings.Labels,
			Components:   effective.Settings.Components,
			PriorityName: priority,
			IssueFields:  issueFields,
		}
		now := time.Now().UTC()
		mappingUpsertBase := store.JiraIssueMappingUpsertInput{
			ProjectID:               *job.ProjectID,
			ConfigLevel:             ownerLevel,
			ConfigTargetID:          ownerTargetID,
			AlertGroupID:            *job.GroupID,
			DedupRuleID:             dedupRuleID,
			TestID:                  &testID,
			ComponentPURL:           item.componentPURL,
			EffectiveConfigLevel:    &ownerLevel,
			EffectiveConfigTargetID: &ownerTargetID,
			Status:                  store.JiraIssueMappingStatusOpen,
			LastSyncedAt:            &now,
			LastError:               "",
			ClosedAt:                nil,
		}

		currentMapping := mapping
		if currentMapping == nil {
			createdMapping, createMappingErr := st.UpsertJiraIssueMapping(mappingUpsertBase)
			if createMappingErr != nil {
				recordJiraAttempt(st, job, store.JiraDeliveryActionNoop, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, nil, createMappingErr)
				return createMappingErr
			}
			currentMapping = createdMapping
		}

		createOrReplaceIssue := func(existingMapping *store.JiraIssueMapping, reason string) (*store.JiraIssueMapping, error) {
			updatedIssueFields, epicErr := ensureJiraEpicKeyForDispatch(
				ctx,
				st,
				*job.ProjectID,
				cfg,
				ownerLevel,
				ownerTargetID,
				effective.Settings,
				group,
				names,
				priority,
			)
			if epicErr != nil {
				recordJiraAttempt(st, job, store.JiraDeliveryActionCreate, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &existingMapping.ID, epicErr)
				emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Failed to prepare Jira epic mapping for issue.", map[string]any{
					"configLevel":    string(ownerLevel),
					"configTargetId": ownerTargetID.String(),
					"alertGroupId":   job.GroupID.String(),
					"componentPurl":  item.componentPURL,
					"error":          epicErr.Error(),
				})
				return nil, epicErr
			}
			issuePayload.IssueFields = updatedIssueFields

			ref, createErr := JiraCreateIssue(ctx, cfg, issuePayload)
			if createErr != nil {
				recordJiraAttempt(st, job, store.JiraDeliveryActionCreate, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &existingMapping.ID, createErr)
				emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Failed to create Jira issue.", map[string]any{
					"configLevel":    string(ownerLevel),
					"configTargetId": ownerTargetID.String(),
					"alertGroupId":   job.GroupID.String(),
					"componentPurl":  item.componentPURL,
					"error":          createErr.Error(),
				})
				return nil, createErr
			}
			updated, upsertErr := st.UpsertJiraIssueMapping(store.JiraIssueMappingUpsertInput{
				ProjectID:               mappingUpsertBase.ProjectID,
				ConfigLevel:             mappingUpsertBase.ConfigLevel,
				ConfigTargetID:          mappingUpsertBase.ConfigTargetID,
				AlertGroupID:            mappingUpsertBase.AlertGroupID,
				DedupRuleID:             mappingUpsertBase.DedupRuleID,
				TestID:                  mappingUpsertBase.TestID,
				ComponentPURL:           mappingUpsertBase.ComponentPURL,
				EffectiveConfigLevel:    mappingUpsertBase.EffectiveConfigLevel,
				EffectiveConfigTargetID: mappingUpsertBase.EffectiveConfigTargetID,
				JiraIssueKey:            strings.TrimSpace(ref.Key),
				JiraIssueID:             strings.TrimSpace(ref.ID),
				Status:                  mappingUpsertBase.Status,
				LastSyncedAt:            mappingUpsertBase.LastSyncedAt,
				LastError:               mappingUpsertBase.LastError,
				ClosedAt:                mappingUpsertBase.ClosedAt,
			})
			if upsertErr != nil {
				recordJiraAttempt(st, job, store.JiraDeliveryActionCreate, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &existingMapping.ID, upsertErr)
				return nil, upsertErr
			}
			recordJiraAttempt(st, job, store.JiraDeliveryActionCreate, store.JiraDeliveryOutcomeSuccess, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &updated.ID, nil)
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.issue_create", eventmeta.SeverityInfo, "Jira issue created", "Created Jira issue for component malware lifecycle.", map[string]any{
				"configLevel":    string(ownerLevel),
				"configTargetId": ownerTargetID.String(),
				"alertGroupId":   job.GroupID.String(),
				"testId":         testID.String(),
				"componentPurl":  item.componentPURL,
				"jiraIssueKey":   updated.JiraIssueKey,
				"jiraIssueId":    updated.JiraIssueID,
				"createReason":   strings.TrimSpace(reason),
			})
			return updated, nil
		}

		issueIDOrKey := jiraIssueIDOrKey(*currentMapping)
		if issueIDOrKey == "" {
			if _, createErr := createOrReplaceIssue(currentMapping, "missing_issue_reference"); createErr != nil {
				return createErr
			}
			reconciledCount++
			continue
		}

		if currentMapping.Status != store.JiraIssueMappingStatusOpen {
			openTransitionName := strings.TrimSpace(effective.Settings.OpenTransitionName)
			if openTransitionName == "" {
				reopenErr := errors.New("jira open transition is required to reopen a closed issue")
				recordJiraAttempt(st, job, store.JiraDeliveryActionReopen, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, reopenErr)
				return reopenErr
			}
			if reopenErr := resolveIssueWithTransitionCache(ctx, st, *job.ProjectID, cfg, issueIDOrKey, openTransitionName); reopenErr != nil {
				if jiraIssueInaccessible(reopenErr) {
					recordJiraAttempt(st, job, store.JiraDeliveryActionReopen, store.JiraDeliveryOutcomeSkipped, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, reopenErr)
					if _, createErr := createOrReplaceIssue(currentMapping, "reopen_target_inaccessible"); createErr != nil {
						return createErr
					}
					reconciledCount++
					continue
				}
				recordJiraAttempt(st, job, store.JiraDeliveryActionReopen, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, reopenErr)
				emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Failed to reopen Jira issue for active malware component.", map[string]any{
					"configLevel":    string(ownerLevel),
					"configTargetId": ownerTargetID.String(),
					"alertGroupId":   job.GroupID.String(),
					"testId":         testID.String(),
					"componentPurl":  item.componentPURL,
					"jiraIssueKey":   currentMapping.JiraIssueKey,
					"jiraIssueId":    currentMapping.JiraIssueID,
					"error":          reopenErr.Error(),
				})
				return reopenErr
			}
			recordJiraAttempt(st, job, store.JiraDeliveryActionReopen, store.JiraDeliveryOutcomeSuccess, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, nil)
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.issue_reopen", eventmeta.SeverityInfo, "Jira issue reopened", "Reopened closed Jira issue because malware is still active for component.", map[string]any{
				"configLevel":    string(ownerLevel),
				"configTargetId": ownerTargetID.String(),
				"alertGroupId":   job.GroupID.String(),
				"testId":         testID.String(),
				"componentPurl":  item.componentPURL,
				"jiraIssueKey":   currentMapping.JiraIssueKey,
				"jiraIssueId":    currentMapping.JiraIssueID,
			})
		}

		if updateErr := JiraUpdateIssue(ctx, cfg, issueIDOrKey, issuePayload); updateErr != nil {
			if jiraIssueInaccessible(updateErr) {
				recordJiraAttempt(st, job, store.JiraDeliveryActionUpdate, store.JiraDeliveryOutcomeSkipped, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, updateErr)
				if _, createErr := createOrReplaceIssue(currentMapping, "update_target_inaccessible"); createErr != nil {
					return createErr
				}
				reconciledCount++
				continue
			}
			recordJiraAttempt(st, job, store.JiraDeliveryActionUpdate, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, updateErr)
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_failed", eventmeta.SeverityError, "Jira sync failed", "Failed to update Jira issue.", map[string]any{
				"configLevel":    string(ownerLevel),
				"configTargetId": ownerTargetID.String(),
				"alertGroupId":   job.GroupID.String(),
				"testId":         testID.String(),
				"componentPurl":  item.componentPURL,
				"jiraIssueKey":   currentMapping.JiraIssueKey,
				"jiraIssueId":    currentMapping.JiraIssueID,
				"error":          updateErr.Error(),
			})
			return updateErr
		}
		updated, upsertErr := st.UpsertJiraIssueMapping(store.JiraIssueMappingUpsertInput{
			ProjectID:               mappingUpsertBase.ProjectID,
			ConfigLevel:             mappingUpsertBase.ConfigLevel,
			ConfigTargetID:          mappingUpsertBase.ConfigTargetID,
			AlertGroupID:            mappingUpsertBase.AlertGroupID,
			DedupRuleID:             mappingUpsertBase.DedupRuleID,
			TestID:                  mappingUpsertBase.TestID,
			ComponentPURL:           mappingUpsertBase.ComponentPURL,
			EffectiveConfigLevel:    mappingUpsertBase.EffectiveConfigLevel,
			EffectiveConfigTargetID: mappingUpsertBase.EffectiveConfigTargetID,
			JiraIssueKey:            currentMapping.JiraIssueKey,
			JiraIssueID:             currentMapping.JiraIssueID,
			Status:                  mappingUpsertBase.Status,
			LastSyncedAt:            mappingUpsertBase.LastSyncedAt,
			LastError:               mappingUpsertBase.LastError,
			ClosedAt:                mappingUpsertBase.ClosedAt,
		})
		if upsertErr != nil {
			recordJiraAttempt(st, job, store.JiraDeliveryActionUpdate, store.JiraDeliveryOutcomeFailed, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &currentMapping.ID, upsertErr)
			return upsertErr
		}
		recordJiraAttempt(st, job, store.JiraDeliveryActionUpdate, store.JiraDeliveryOutcomeSuccess, *job.ProjectID, &ownerLevel, &ownerTargetID, job.GroupID, dedupRuleID, &updated.ID, nil)
		emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.issue_update", eventmeta.SeverityInfo, "Jira issue updated", "Updated Jira issue for component malware lifecycle.", map[string]any{
			"configLevel":    string(ownerLevel),
			"configTargetId": ownerTargetID.String(),
			"alertGroupId":   job.GroupID.String(),
			"testId":         testID.String(),
			"componentPurl":  item.componentPURL,
			"jiraIssueKey":   updated.JiraIssueKey,
			"jiraIssueId":    updated.JiraIssueID,
		})
		reconciledCount++
	}

	emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.issue_lifecycle_reconciled", eventmeta.SeverityInfo, "Jira issue lifecycle reconciled", "Jira component lifecycle reconciliation completed.", map[string]any{
		"alertGroupId":      job.GroupID.String(),
		"eventState":        string(eventState),
		"componentsHandled": len(componentCtxByKey),
		"reconciledCount":   reconciledCount,
	})
	emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_succeeded", eventmeta.SeverityInfo, "Jira sync succeeded", "Jira synchronization completed.", map[string]any{
		"alertGroupId": job.GroupID.String(),
		"eventState":   string(eventState),
	})
	logger.Info("jira component lifecycle processed", "project_id", *job.ProjectID, "group_id", *job.GroupID, "components", len(componentCtxByKey), "reconciled", reconciledCount)
	return nil
}
