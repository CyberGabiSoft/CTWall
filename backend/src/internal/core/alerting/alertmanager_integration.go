package alerting

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"backend/internal/audit"
	"backend/internal/eventmeta"
	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"
)

type AlertmanagerIntegrationConfig struct {
	ConfigFilePath       string
	PublicBaseURL        string
	ControlPollInterval  time.Duration
	DispatchPollInterval time.Duration
	HeartbeatInterval    time.Duration
	DispatchWorkers      int
	ClaimBatchSize       int
	RetryMaxAttempts     int
	RetryMaxWindow       time.Duration
	RouteGroupBy         []string
	RouteGroupWait       time.Duration
	RouteGroupInterval   time.Duration
	RouteRepeatInterval  time.Duration
}

// firingAlertEndsAtHorizon keeps FIRING alerts active in Alertmanager until
// CTWall explicitly sends RESOLVED (group close / triage-driven closure).
// Without EndsAt, Alertmanager can auto-resolve after resolve_timeout
// (commonly 5m), which is not the desired CTWall behavior.
const firingAlertEndsAtHorizon = 10 * 365 * 24 * time.Hour

func DefaultAlertmanagerIntegrationConfig() AlertmanagerIntegrationConfig {
	return AlertmanagerIntegrationConfig{
		ConfigFilePath:       "",
		PublicBaseURL:        "",
		ControlPollInterval:  10 * time.Second,
		DispatchPollInterval: 3 * time.Second,
		HeartbeatInterval:    5 * time.Minute,
		DispatchWorkers:      2,
		ClaimBatchSize:       20,
		RetryMaxAttempts:     50,
		RetryMaxWindow:       72 * time.Hour,
		RouteGroupBy:         []string{"project_id", "severity", "category", "alert_type", "dedup_key"},
		RouteGroupWait:       30 * time.Second,
		RouteGroupInterval:   5 * time.Minute,
		RouteRepeatInterval:  30 * time.Minute,
	}
}

func (cfg *AlertmanagerIntegrationConfig) normalize() {
	if cfg.ControlPollInterval <= 0 {
		cfg.ControlPollInterval = 10 * time.Second
	}
	if cfg.DispatchPollInterval <= 0 {
		cfg.DispatchPollInterval = 3 * time.Second
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 5 * time.Minute
	}
	if cfg.DispatchWorkers < 1 {
		cfg.DispatchWorkers = 1
	}
	if cfg.ClaimBatchSize < 1 {
		cfg.ClaimBatchSize = 20
	}
	if cfg.RetryMaxAttempts < 1 {
		cfg.RetryMaxAttempts = 50
	}
	if cfg.RetryMaxWindow <= 0 {
		cfg.RetryMaxWindow = 72 * time.Hour
	}
	if len(cfg.RouteGroupBy) == 0 {
		cfg.RouteGroupBy = []string{"project_id", "severity", "category", "alert_type", "dedup_key"}
	}
	if cfg.RouteGroupWait <= 0 {
		cfg.RouteGroupWait = 30 * time.Second
	}
	if cfg.RouteGroupInterval <= 0 {
		cfg.RouteGroupInterval = 5 * time.Minute
	}
	if cfg.RouteRepeatInterval <= 0 {
		cfg.RouteRepeatInterval = 30 * time.Minute
	}
	cfg.PublicBaseURL = strings.TrimSpace(cfg.PublicBaseURL)
	cfg.ConfigFilePath = strings.TrimSpace(cfg.ConfigFilePath)
}

func StartAlertmanagerIntegration(ctx context.Context, st store.Store, client *AlertmanagerClient, cfg AlertmanagerIntegrationConfig, logger *slog.Logger) {
	if st == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	cfg.normalize()

	if client != nil {
		_, _ = st.EnqueueAlertDispatchJob(store.AlertDispatchEnqueueInput{
			MessageType: store.AlertDispatchMessageTypeConfigApply,
			PayloadJSON: []byte(`{"reason":"startup_bootstrap"}`),
		})
	}
	if count, err := st.RequeueStaleAlertDispatchJobs(5*time.Minute, 0); err != nil {
		logger.Warn("alerting stale-job recovery failed", "component", "alerting.bootstrap", "error", err)
	} else if count > 0 {
		logger.Warn("alerting stale jobs requeued", "component", "alerting.bootstrap", "count", count)
	}

	if client != nil {
		go runAlertmanagerControlLoop(ctx, st, client, cfg, logger.With("component", "alerting.control"))
	}
	go runAlertHeartbeatLoop(ctx, st, cfg, logger.With("component", "alerting.heartbeat"))
	for i := 0; i < cfg.DispatchWorkers; i++ {
		workerID := fmt.Sprintf("alert-dispatcher-%d", i+1)
		go runAlertDispatchLoop(ctx, st, client, cfg, workerID, logger.With("component", "alerting.dispatch", "worker_id", workerID))
	}
}

func runAlertmanagerControlLoop(ctx context.Context, st store.Store, client *AlertmanagerClient, cfg AlertmanagerIntegrationConfig, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.ControlPollInterval)
	defer ticker.Stop()
	logger.Info("alertmanager control loop started")
	defer logger.Info("alertmanager control loop stopped")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			jobs, err := st.ClaimAlertDispatchJobs(store.AlertDispatchMessageTypeConfigApply, cfg.ClaimBatchSize, "alert-control")
			if err != nil {
				logger.Error("claim config jobs failed", "error", err)
				continue
			}
			if len(jobs) == 0 {
				continue
			}
			for _, job := range jobs {
				if err := processConfigApplyJob(ctx, st, client, cfg, job, logger); err != nil {
					logger.Error("config apply job failed", "job_id", job.ID, "error", err)
				}
			}
		}
	}
}

func processConfigApplyJob(ctx context.Context, st store.Store, client *AlertmanagerClient, cfg AlertmanagerIntegrationConfig, job store.AlertDispatchJob, logger *slog.Logger) error {
	if strings.TrimSpace(cfg.ConfigFilePath) == "" {
		return markJobDoneWithLog(st, job.ID, logger, "config_file_path is empty; skipping config apply")
	}
	data, err := renderAlertmanagerYAML(st, cfg)
	if err != nil {
		return handleDispatchFailure(st, cfg, job, err, logger)
	}
	if err := writeFileAtomic(cfg.ConfigFilePath, data); err != nil {
		return handleDispatchFailure(st, cfg, job, err, logger)
	}
	reloadCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Reload(reloadCtx); err != nil {
		return handleDispatchFailure(st, cfg, job, err, logger)
	}
	if err := st.MarkAlertDispatchJobDone(job.ID); err != nil {
		return err
	}
	return nil
}

func runAlertDispatchLoop(ctx context.Context, st store.Store, client *AlertmanagerClient, cfg AlertmanagerIntegrationConfig, workerID string, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.DispatchPollInterval)
	defer ticker.Stop()
	logger.Info("alert dispatch loop started")
	defer logger.Info("alert dispatch loop stopped")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			jobs, err := st.ClaimAlertDispatchJobs(store.AlertDispatchMessageTypeAlertEvent, cfg.ClaimBatchSize, workerID)
			if err != nil {
				logger.Error("claim alert jobs failed", "error", err)
				continue
			}
			for _, job := range jobs {
				if err := processAlertEventJob(ctx, st, client, cfg, job, logger); err != nil {
					logger.Error("alert dispatch job failed", "job_id", job.ID, "error", err)
				}
			}
		}
	}
}

func processAlertEventJob(ctx context.Context, st store.Store, client *AlertmanagerClient, cfg AlertmanagerIntegrationConfig, job store.AlertDispatchJob, logger *slog.Logger) error {
	if job.ProjectID == nil || job.GroupID == nil || job.EventState == nil {
		_ = st.MarkAlertDispatchJobDead(job.ID, "invalid_job", "missing project/group/event state")
		return nil
	}
	group, err := st.GetAlertGroup(*job.ProjectID, *job.GroupID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return st.MarkAlertDispatchJobDone(job.ID)
		}
		return handleDispatchFailure(st, cfg, job, err, logger)
	}

	eventState := *job.EventState
	connectorTypes, routeErr := matchingConnectorTypesForDispatch(st, *job.ProjectID, *job.GroupID, eventState)
	if routeErr != nil {
		return handleDispatchFailure(st, cfg, job, routeErr, logger)
	}
	if len(connectorTypes) == 0 {
		return st.MarkAlertDispatchJobDone(job.ID)
	}
	nonJiraConnectorTypes, externalConnectorTypes, dispatchJira := partitionDispatchConnectorTypes(connectorTypes)
	if len(nonJiraConnectorTypes) == 0 && len(externalConnectorTypes) == 0 && !dispatchJira {
		return st.MarkAlertDispatchJobDone(job.ID)
	}

	switch eventState {
	case store.AlertDispatchEventStateFiring:
	case store.AlertDispatchEventStateResolve:
		if !strings.EqualFold(strings.TrimSpace(group.Status), string(store.AlertGroupStatusClosed)) {
			// Resolve events must only be dispatched for explicitly CLOSED groups.
			// This prevents accidental resolved notifications for OPEN/ACKNOWLEDGED
			// states when stale resolve jobs are still in queue.
			return st.MarkAlertDispatchJobDone(job.ID)
		}
		if group.LastNotifiedAt == nil && !dispatchJira {
			return st.MarkAlertDispatchJobDone(job.ID)
		}
	default:
		_ = st.MarkAlertDispatchJobDead(job.ID, "invalid_event_state", string(eventState))
		return nil
	}

	var latestCtx *store.AlertOccurrenceContext
	if ctx, ctxErr := st.GetLatestAlertOccurrenceContext(*job.ProjectID, *job.GroupID); ctxErr == nil {
		latestCtx = ctx
	} else if !errors.Is(ctxErr, store.ErrNotFound) {
		logger.Warn("latest alert occurrence context lookup failed", "project_id", *job.ProjectID, "group_id", *job.GroupID, "error", ctxErr)
	}
	entityNames := loadAlertEntityNames(st, group.ProjectID, latestCtx)

	dispatchAttempted := false
	dispatchSucceeded := false
	var firstDispatchErr error
	var externalDispatchErr error
	var jiraDispatchErr error
	if len(nonJiraConnectorTypes) > 0 {
		dispatchAttempted = true
		if client == nil {
			firstDispatchErr = errors.New("alertmanager client is required for non-jira connector dispatch")
		} else {
			alerts := make([]AlertmanagerAlert, 0, len(nonJiraConnectorTypes))
			for _, connectorType := range nonJiraConnectorTypes {
				alerts = append(alerts, buildAlertmanagerAlert(*group, eventState, cfg.PublicBaseURL, connectorType, latestCtx, entityNames))
			}
			sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := client.PostAlerts(sendCtx, alerts)
			cancel()
			if err != nil {
				firstDispatchErr = err
			} else {
				dispatchSucceeded = true
			}
		}
	}
	if len(externalConnectorTypes) > 0 {
		dispatchAttempted = true
		if err := dispatchExternalAlertmanagerConnectors(ctx, st, cfg.PublicBaseURL, *job.ProjectID, *group, eventState, latestCtx, externalConnectorTypes); err != nil {
			externalDispatchErr = err
			if firstDispatchErr == nil {
				firstDispatchErr = err
			}
			emitExternalAlertmanagerDispatchEvent(st, *job.ProjectID, job.GroupID, "alerting.alertmanager_external.dispatch_failed", eventmeta.SeverityError, "External Alertmanager dispatch failed", "Failed to dispatch alert to external Alertmanager.", map[string]any{
				"alertGroupId": job.GroupID.String(),
				"eventState":   string(eventState),
				"attempt":      job.AttemptCount,
				"error":        err.Error(),
			})
		} else {
			dispatchSucceeded = true
		}
	}
	if dispatchJira {
		dispatchAttempted = true
		emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_started", eventmeta.SeverityInfo, "Jira sync started", "Started Jira synchronization for alert dispatch job.", map[string]any{
			"alertGroupId": job.GroupID.String(),
			"eventState":   string(eventState),
			"attempt":      job.AttemptCount,
		})
		if err := processJiraAlertEventJobWithConfiguredRetry(ctx, st, job, group, eventState, logger); err != nil {
			jiraDispatchErr = err
			if firstDispatchErr == nil {
				firstDispatchErr = err
			}
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.delivery_failed", eventmeta.SeverityError, "Jira delivery failed", "Jira delivery attempt failed.", map[string]any{
				"alertGroupId": job.GroupID.String(),
				"eventState":   string(eventState),
				"attempt":      job.AttemptCount,
				"error":        err.Error(),
			})
		} else {
			dispatchSucceeded = true
		}
	}
	if dispatchSucceeded {
		now := time.Now().UTC()
		_ = st.UpdateAlertGroupLastNotifiedAt(*job.ProjectID, *job.GroupID, now)
		if err := st.MarkAlertDispatchJobDone(job.ID); err != nil {
			return err
		}
		return nil
	}
	if !dispatchAttempted {
		return st.MarkAlertDispatchJobDone(job.ID)
	}
	if externalDispatchErr != nil && shouldMarkDispatchJobDead(job, cfg, externalDispatchErr) {
		emitExternalAlertmanagerDispatchEvent(st, *job.ProjectID, job.GroupID, "alerting.alertmanager_external.dispatch_dead_letter", eventmeta.SeverityError, "External Alertmanager dead-letter", "External Alertmanager dispatch reached dead-letter state.", map[string]any{
			"alertGroupId": job.GroupID.String(),
			"eventState":   string(eventState),
			"attempt":      job.AttemptCount,
			"error":        externalDispatchErr.Error(),
		})
	}
	if jiraDispatchErr != nil {
		if shouldMarkDispatchJobDead(job, cfg, jiraDispatchErr) {
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_dead_letter", eventmeta.SeverityError, "Jira sync dead-letter", "Jira synchronization reached dead-letter state.", map[string]any{
				"alertGroupId": job.GroupID.String(),
				"eventState":   string(eventState),
				"attempt":      job.AttemptCount,
				"error":        jiraDispatchErr.Error(),
			})
		} else {
			emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_retry_scheduled", eventmeta.SeverityError, "Jira sync retry scheduled", "Jira synchronization failed and was scheduled for retry.", map[string]any{
				"alertGroupId": job.GroupID.String(),
				"eventState":   string(eventState),
				"attempt":      job.AttemptCount,
				"error":        jiraDispatchErr.Error(),
			})
		}
	}
	if firstDispatchErr == nil {
		firstDispatchErr = errors.New("alert dispatch failed: no connector delivery succeeded")
	}
	return handleDispatchFailure(st, cfg, job, firstDispatchErr, logger)
}

func partitionDispatchConnectorTypes(connectorTypes []store.ConnectorType) ([]store.ConnectorType, []store.ConnectorType, bool) {
	nonJiraConnectorTypes := make([]store.ConnectorType, 0, len(connectorTypes))
	externalConnectorTypes := make([]store.ConnectorType, 0, len(connectorTypes))
	dispatchJira := false
	for _, connectorType := range connectorTypes {
		switch connectorType {
		case store.ConnectorTypeJira:
			dispatchJira = true
		case store.ConnectorTypeAlertmanagerExternal:
			externalConnectorTypes = append(externalConnectorTypes, connectorType)
		default:
			nonJiraConnectorTypes = append(nonJiraConnectorTypes, connectorType)
		}
	}
	return nonJiraConnectorTypes, externalConnectorTypes, dispatchJira
}

func shouldMarkDispatchJobDead(job store.AlertDispatchJob, cfg AlertmanagerIntegrationConfig, err error) bool {
	if !isRetryableAlertmanagerError(err) {
		return true
	}
	if job.AttemptCount >= cfg.RetryMaxAttempts {
		return true
	}
	return time.Now().UTC().After(job.CreatedAt.Add(cfg.RetryMaxWindow))
}

func resolveJiraRetryPolicyForJob(st store.Store, projectID, groupID uuid.UUID) (int, time.Duration) {
	attempts := store.JiraDeliveryRetryAttemptsDefault
	backoffSeconds := store.JiraDeliveryRetryBackoffSecondsDefault
	if st == nil {
		return attempts, time.Duration(backoffSeconds) * time.Second
	}
	occCtx, err := st.GetLatestAlertOccurrenceContext(projectID, groupID)
	if err != nil || occCtx == nil || occCtx.ProductID == nil || occCtx.ScopeID == nil || occCtx.TestID == nil {
		return attempts, time.Duration(backoffSeconds) * time.Second
	}
	effective, resolveErr := st.ResolveEffectiveJiraSettings(store.JiraEffectiveSettingsResolveInput{
		ProjectID: projectID,
		ProductID: occCtx.ProductID,
		ScopeID:   occCtx.ScopeID,
		TestID:    occCtx.TestID,
	})
	if resolveErr != nil || effective == nil {
		return attempts, time.Duration(backoffSeconds) * time.Second
	}
	attempts = effective.Settings.DeliveryRetryAttempts
	backoffSeconds = effective.Settings.DeliveryRetryBackoffSeconds
	if attempts < store.JiraDeliveryRetryAttemptsMin {
		attempts = store.JiraDeliveryRetryAttemptsDefault
	}
	if attempts > store.JiraDeliveryRetryAttemptsMax {
		attempts = store.JiraDeliveryRetryAttemptsMax
	}
	if backoffSeconds < store.JiraDeliveryRetryBackoffSecondsMin {
		backoffSeconds = store.JiraDeliveryRetryBackoffSecondsDefault
	}
	if backoffSeconds > store.JiraDeliveryRetryBackoffSecondsMax {
		backoffSeconds = store.JiraDeliveryRetryBackoffSecondsMax
	}
	return attempts, time.Duration(backoffSeconds) * time.Second
}

func processJiraAlertEventJobWithConfiguredRetry(
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
	retryAttempts, backoff := resolveJiraRetryPolicyForJob(st, *job.ProjectID, *job.GroupID)
	if backoff <= 0 {
		backoff = time.Duration(store.JiraDeliveryRetryBackoffSecondsDefault) * time.Second
	}

	var lastErr error
	totalAttempts := retryAttempts + 1
	for run := 1; run <= totalAttempts; run++ {
		lastErr = processJiraAlertEventJob(ctx, st, job, group, eventState, logger)
		if lastErr == nil {
			return nil
		}
		if run >= totalAttempts || !isRetryableAlertmanagerError(lastErr) {
			break
		}
		emitJiraSyncEvent(st, *job.ProjectID, job.GroupID, "alerting.jira.sync_internal_retry", eventmeta.SeverityWarn, "Jira sync retry in progress", "Retrying Jira synchronization within current dispatch attempt.", map[string]any{
			"alertGroupId": job.GroupID.String(),
			"attempt":      job.AttemptCount,
			"retryIndex":   run,
			"retryMax":     retryAttempts,
			"backoff":      backoff.String(),
			"error":        lastErr.Error(),
		})
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func runAlertHeartbeatLoop(ctx context.Context, st store.Store, cfg AlertmanagerIntegrationConfig, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()
	logger.Info("alert heartbeat loop started")
	defer logger.Info("alert heartbeat loop stopped")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			groups, err := st.ListOpenAlertGroupsForHeartbeat(500, cfg.HeartbeatInterval)
			if err != nil {
				logger.Error("heartbeat fetch failed", "error", err)
				continue
			}
			if len(groups) == 0 {
				continue
			}
			now := time.Now().UTC()
			expires := now.Add(cfg.RetryMaxWindow)
			state := store.AlertDispatchEventStateFiring
			for _, group := range groups {
				projectID := group.ProjectID
				groupID := group.ID
				_, enqueueErr := st.EnqueueAlertDispatchJob(store.AlertDispatchEnqueueInput{
					MessageType: store.AlertDispatchMessageTypeAlertEvent,
					EventState:  &state,
					ProjectID:   &projectID,
					GroupID:     &groupID,
					PayloadJSON: []byte(`{"reason":"active_refresh"}`),
					ExpiresAt:   &expires,
				})
				if enqueueErr != nil {
					logger.Warn("heartbeat enqueue failed", "group_id", group.ID, "error", enqueueErr)
				}
			}
		}
	}
}

func matchingConnectorTypesForDispatch(st store.Store, projectID, groupID uuid.UUID, eventState store.AlertDispatchEventState) ([]store.ConnectorType, error) {
	settings, err := st.GetAlertConnectorSettings(projectID)
	if err != nil {
		return nil, err
	}

	var ctx *store.AlertOccurrenceContext
	loadContext := func() error {
		if ctx != nil {
			return nil
		}
		var latestErr error
		ctx, latestErr = st.GetLatestAlertOccurrenceContext(projectID, groupID)
		if errors.Is(latestErr, store.ErrNotFound) {
			ctx = nil
			return nil
		}
		return latestErr
	}

	selected := make([]store.ConnectorType, 0, len(store.AllMVPConnectorTypes()))
	selectedSet := make(map[store.ConnectorType]struct{}, len(store.AllMVPConnectorTypes()))
	explicitSettings := make(map[store.ConnectorType]struct{}, len(settings))
	for _, setting := range settings {
		explicitSettings[setting.ConnectorType] = struct{}{}
		if !setting.IsEnabled || !store.ValidConnectorType(setting.ConnectorType) || !store.IsConnectorTypeEnabledInMVP(setting.ConnectorType) {
			continue
		}
		connectorCfg, cfgErr := st.GetProjectConnectorConfig(projectID, setting.ConnectorType)
		if cfgErr != nil {
			if errors.Is(cfgErr, store.ErrNotFound) {
				continue
			}
			return nil, cfgErr
		}
		if connectorCfg == nil || !connectorCfg.IsEnabled || strings.TrimSpace(string(connectorCfg.ConfigJSON)) == "{}" || strings.TrimSpace(string(connectorCfg.ConfigJSON)) == "" {
			continue
		}

		if eventState == store.AlertDispatchEventStateFiring && len(setting.Routes) > 0 {
			if err := loadContext(); err != nil {
				return nil, err
			}
			if ctx == nil {
				continue
			}
			matchesRoute := false
			for _, route := range setting.Routes {
				switch route.TargetType {
				case store.AlertRouteTargetProduct:
					if ctx.ProductID != nil && *ctx.ProductID == route.TargetID {
						matchesRoute = true
					}
				case store.AlertRouteTargetScope:
					if ctx.ScopeID != nil && *ctx.ScopeID == route.TargetID {
						matchesRoute = true
					}
				case store.AlertRouteTargetTest:
					if ctx.TestID != nil && *ctx.TestID == route.TargetID {
						matchesRoute = true
					}
				}
				if matchesRoute {
					break
				}
			}
			if !matchesRoute {
				continue
			}
		}

		if _, exists := selectedSet[setting.ConnectorType]; !exists {
			selected = append(selected, setting.ConnectorType)
			selectedSet[setting.ConnectorType] = struct{}{}
		}
	}

	// Backward-compatible implicit routing:
	// if connector config is enabled and no explicit alert routing row exists,
	// dispatch project-wide by default.
	for _, connectorType := range store.AllMVPConnectorTypes() {
		if !store.IsConnectorTypeEnabledInMVP(connectorType) {
			continue
		}
		if _, hasExplicitSetting := explicitSettings[connectorType]; hasExplicitSetting {
			continue
		}
		if _, alreadySelected := selectedSet[connectorType]; alreadySelected {
			continue
		}
		connectorCfg, cfgErr := st.GetProjectConnectorConfig(projectID, connectorType)
		if cfgErr != nil {
			if errors.Is(cfgErr, store.ErrNotFound) {
				continue
			}
			return nil, cfgErr
		}
		if connectorCfg == nil || !connectorCfg.IsEnabled {
			continue
		}
		configPayload := strings.TrimSpace(string(connectorCfg.ConfigJSON))
		if configPayload == "" || configPayload == "{}" {
			continue
		}
		selected = append(selected, connectorType)
		selectedSet[connectorType] = struct{}{}
	}

	return selected, nil
}

func buildAlertmanagerAlert(group models.AlertGroup, eventState store.AlertDispatchEventState, publicBaseURL string, connectorType store.ConnectorType, occurrenceCtx *store.AlertOccurrenceContext, entityNames alertEntityNames) AlertmanagerAlert {
	alertType := strings.TrimSpace(group.Type)
	if alertType == "" {
		alertType = "alert"
	}
	projectLabel := strings.TrimSpace(entityNames.project)
	if projectLabel == "" {
		projectLabel = group.ProjectID.String()
	}
	labels := map[string]string{
		"alertname":      alertType,
		"project":        projectLabel,
		"project_id":     group.ProjectID.String(),
		"severity":       strings.ToUpper(strings.TrimSpace(string(group.Severity))),
		"category":       strings.TrimSpace(string(group.Category)),
		"alert_type":     alertType,
		"dedup_key":      strings.TrimSpace(group.GroupKey),
		"group_key":      strings.TrimSpace(group.GroupKey),
		"finding_count":  strconv.Itoa(group.Occurrences),
		"connector_type": strings.ToLower(strings.TrimSpace(string(connectorType))),
	}
	if occurrenceCtx != nil {
		if occurrenceCtx.ProductID != nil {
			labels["product_id"] = occurrenceCtx.ProductID.String()
		}
		if occurrenceCtx.ScopeID != nil {
			labels["scope_id"] = occurrenceCtx.ScopeID.String()
		}
		if occurrenceCtx.TestID != nil {
			labels["test_id"] = occurrenceCtx.TestID.String()
		}
	}
	if productLabel := strings.TrimSpace(entityNames.product); productLabel != "" {
		labels["product"] = productLabel
	}
	if scopeLabel := strings.TrimSpace(entityNames.scope); scopeLabel != "" {
		labels["scope"] = scopeLabel
	}
	if testLabel := strings.TrimSpace(entityNames.test); testLabel != "" {
		labels["test"] = testLabel
	}
	if group.EntityRef != nil {
		if componentPURL := strings.TrimSpace(*group.EntityRef); componentPURL != "" {
			labels["component_purl"] = componentPURL
		}
	}
	for key, value := range labels {
		if strings.TrimSpace(value) == "" {
			delete(labels, key)
		}
	}
	alertURL := ""
	if baseURL := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/"); baseURL != "" {
		alertURL = baseURL + "/security/alerts"
	}
	annotations := map[string]string{
		"title":       strings.TrimSpace(group.Title),
		"description": strings.TrimSpace(buildAlertDescription(group, occurrenceCtx, entityNames, alertURL)),
	}
	if alertURL != "" {
		annotations["alert_url"] = alertURL
	}
	if group.EntityRef != nil {
		if entity := strings.TrimSpace(*group.EntityRef); entity != "" {
			annotations["entity_ref"] = entity
		}
	}
	startsAt := group.FirstSeenAt.UTC().Format(time.RFC3339)
	alert := AlertmanagerAlert{
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    startsAt,
	}
	if alertURL != "" {
		alert.GeneratorURL = alertURL
	}
	if eventState == store.AlertDispatchEventStateResolve {
		alert.EndsAt = time.Now().UTC().Format(time.RFC3339)
	} else if eventState == store.AlertDispatchEventStateFiring {
		alert.EndsAt = time.Now().UTC().Add(firingAlertEndsAtHorizon).Format(time.RFC3339)
	}
	return alert
}

func buildAlertDescription(
	group models.AlertGroup,
	occurrenceCtx *store.AlertOccurrenceContext,
	entityNames alertEntityNames,
	alertURL string,
) string {
	lines := make([]string, 0, 9)
	title := strings.TrimSpace(group.Title)
	if title != "" {
		lines = append(lines, title)
	}
	if severity := strings.ToUpper(strings.TrimSpace(string(group.Severity))); severity != "" {
		lines = append(lines, "Severity: "+severity)
	}
	projectName := strings.TrimSpace(entityNames.project)
	if projectName == "" {
		projectName = group.ProjectID.String()
	}
	lines = append(lines, "Project: "+projectName)

	if occurrenceCtx != nil && occurrenceCtx.ProductID != nil {
		productName := strings.TrimSpace(entityNames.product)
		if productName == "" {
			productName = occurrenceCtx.ProductID.String()
		}
		lines = append(lines, "Product: "+productName)
	}
	if occurrenceCtx != nil && occurrenceCtx.ScopeID != nil {
		scopeName := strings.TrimSpace(entityNames.scope)
		if scopeName == "" {
			scopeName = occurrenceCtx.ScopeID.String()
		}
		lines = append(lines, "Scope: "+scopeName)
	}
	if occurrenceCtx != nil && occurrenceCtx.TestID != nil {
		testName := strings.TrimSpace(entityNames.test)
		if testName == "" {
			testName = occurrenceCtx.TestID.String()
		}
		lines = append(lines, "Test: "+testName)
	}

	if group.EntityRef != nil {
		if entity := strings.TrimSpace(*group.EntityRef); entity != "" {
			lines = append(lines, "Entity: "+entity)
		}
	}
	lines = append(lines, fmt.Sprintf("Findings: %d", group.Occurrences))
	if alertURL != "" {
		lines = append(lines, "Open in CTWall: "+alertURL)
	}
	return strings.Join(lines, "\n")
}

type alertmanagerConfigFile struct {
	Route     alertmanagerRoute      `yaml:"route"`
	Receivers []alertmanagerReceiver `yaml:"receivers"`
}

type alertmanagerTLSConfig struct {
	CAFile             string `yaml:"ca_file,omitempty"`
	ServerName         string `yaml:"server_name,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}

type alertmanagerRoute struct {
	Receiver       string              `yaml:"receiver"`
	GroupBy        []string            `yaml:"group_by,omitempty"`
	GroupWait      string              `yaml:"group_wait,omitempty"`
	GroupInterval  string              `yaml:"group_interval,omitempty"`
	RepeatInterval string              `yaml:"repeat_interval,omitempty"`
	Matchers       []string            `yaml:"matchers,omitempty"`
	Routes         []alertmanagerRoute `yaml:"routes,omitempty"`
}

type alertmanagerReceiver struct {
	Name            string           `yaml:"name"`
	DiscordConfigs  []map[string]any `yaml:"discord_configs,omitempty"`
	EmailConfigs    []map[string]any `yaml:"email_configs,omitempty"`
	MSTeamsV2Config []map[string]any `yaml:"msteamsv2_configs,omitempty"`
	OpsgenieConfigs []map[string]any `yaml:"opsgenie_configs,omitempty"`
	PagerDutyConfig []map[string]any `yaml:"pagerduty_configs,omitempty"`
	PushoverConfigs []map[string]any `yaml:"pushover_configs,omitempty"`
	RocketChatCfg   []map[string]any `yaml:"rocketchat_configs,omitempty"`
	SlackConfigs    []map[string]any `yaml:"slack_configs,omitempty"`
	SNSConfigs      []map[string]any `yaml:"sns_configs,omitempty"`
	TelegramConfigs []map[string]any `yaml:"telegram_configs,omitempty"`
	VictorOpsConfig []map[string]any `yaml:"victorops_configs,omitempty"`
	WebexConfigs    []map[string]any `yaml:"webex_configs,omitempty"`
	WebhookConfigs  []map[string]any `yaml:"webhook_configs,omitempty"`
	WeChatConfigs   []map[string]any `yaml:"wechat_configs,omitempty"`
}

func renderAlertmanagerYAML(st store.Store, cfg AlertmanagerIntegrationConfig) ([]byte, error) {
	file := alertmanagerConfigFile{
		Route: alertmanagerRoute{
			Receiver:       "blackhole",
			GroupBy:        cfg.RouteGroupBy,
			GroupWait:      cfg.RouteGroupWait.String(),
			GroupInterval:  cfg.RouteGroupInterval.String(),
			RepeatInterval: cfg.RouteRepeatInterval.String(),
		},
		Receivers: []alertmanagerReceiver{{Name: "blackhole"}},
	}

	receiverByFingerprint := make(map[string]string)
	for _, connectorType := range store.AllMVPConnectorTypes() {
		if connectorType == store.ConnectorTypeJira || connectorType == store.ConnectorTypeAlertmanagerExternal {
			// Jira and external Alertmanager are handled by native CTWall dispatcher
			// (not Alertmanager receiver rendering).
			continue
		}
		enabledProjects, err := st.ListEnabledAlertProjects(connectorType)
		if err != nil {
			return nil, err
		}
		for _, projectID := range enabledProjects {
			projectConnector, cfgErr := st.GetProjectConnectorConfig(projectID, connectorType)
			if cfgErr != nil {
				if errors.Is(cfgErr, store.ErrNotFound) {
					continue
				}
				return nil, cfgErr
			}
			if projectConnector == nil || !projectConnector.IsEnabled {
				continue
			}
			configPayload := strings.TrimSpace(string(projectConnector.ConfigJSON))
			if configPayload == "" || configPayload == "{}" {
				continue
			}
			repeatIntervalOverride, routeErr := parseConnectorRouteRepeatInterval(projectConnector.ConfigJSON)
			if routeErr != nil {
				// Connector isolation: a single malformed connector config must not block
				// rendering and delivery for all other connectors/projects.
				continue
			}

			projectAdminEmails := []string(nil)
			if connectorType == store.ConnectorTypeSMTP {
				emails, emailErr := st.ListProjectAdminEmails(projectID)
				if emailErr != nil {
					return nil, emailErr
				}
				projectAdminEmails = emails
			}
			receiverConfig, renderErr := BuildAlertmanagerReceiverConfig(connectorType, projectConnector.ConfigJSON, projectAdminEmails)
			if renderErr != nil {
				// Connector isolation: a single malformed connector config must not block
				// rendering and delivery for all other connectors/projects.
				continue
			}
			serializedConfig, jsonErr := json.Marshal(receiverConfig)
			if jsonErr != nil {
				return nil, jsonErr
			}
			fingerprint := shortSHA1(strings.ToLower(string(connectorType)) + ":" + string(serializedConfig))
			receiverName, exists := receiverByFingerprint[fingerprint]
			if !exists {
				receiverName = strings.ToLower(string(connectorType)) + "_" + fingerprint
				receiver := alertmanagerReceiver{Name: receiverName}
				if addErr := addReceiverConfig(&receiver, connectorType, receiverConfig); addErr != nil {
					return nil, addErr
				}
				file.Receivers = append(file.Receivers, receiver)
				receiverByFingerprint[fingerprint] = receiverName
			}
			file.Route.Routes = append(file.Route.Routes, alertmanagerRoute{
				Receiver: receiverName,
				Matchers: []string{
					fmt.Sprintf(`project_id="%s"`, projectID.String()),
					fmt.Sprintf(`connector_type="%s"`, strings.ToLower(string(connectorType))),
				},
				RepeatInterval: repeatIntervalOverride,
			})
		}
	}

	out, err := yaml.Marshal(file)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func dispatchExternalAlertmanagerConnectors(
	ctx context.Context,
	st store.Store,
	publicBaseURL string,
	projectID uuid.UUID,
	group models.AlertGroup,
	eventState store.AlertDispatchEventState,
	occurrenceCtx *store.AlertOccurrenceContext,
	connectorTypes []store.ConnectorType,
) error {
	entityNames := loadAlertEntityNames(st, projectID, occurrenceCtx)
	for _, connectorType := range connectorTypes {
		if connectorType != store.ConnectorTypeAlertmanagerExternal {
			continue
		}
		connectorCfg, err := st.GetProjectConnectorConfig(projectID, connectorType)
		if err != nil {
			return err
		}
		if connectorCfg == nil || !connectorCfg.IsEnabled {
			continue
		}
		externalCfg, err := ParseExternalAlertmanagerConnectorConfig(connectorCfg.ConfigJSON)
		if err != nil {
			return err
		}
		if eventState == store.AlertDispatchEventStateResolve && !externalCfg.SendResolved {
			continue
		}
		client, err := NewExternalAlertmanagerClient(externalCfg)
		if err != nil {
			return err
		}
		alert := buildAlertmanagerAlert(group, eventState, publicBaseURL, connectorType, occurrenceCtx, entityNames)
		sendCtx, cancel := context.WithTimeout(ctx, time.Duration(externalCfg.TimeoutSeconds)*time.Second)
		err = client.PostAlerts(sendCtx, []AlertmanagerAlert{alert})
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

func emitExternalAlertmanagerDispatchEvent(
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
		Component: "core.alerting.alertmanager_integration",
	}, extra)
	if err != nil {
		return
	}
	_ = st.CreateAuditLog(store.AuditLogEntry{
		Action:     "ALERTMANAGER_EXTERNAL_DISPATCH_EVENT",
		EntityType: "ALERT_GROUP",
		EntityID:   groupID,
		Details:    details,
	})
}

func addReceiverConfig(receiver *alertmanagerReceiver, connectorType store.ConnectorType, cfg map[string]any) error {
	if receiver == nil {
		return fmt.Errorf("receiver is nil")
	}
	switch connectorType {
	case store.ConnectorTypeDiscord:
		receiver.DiscordConfigs = []map[string]any{cfg}
	case store.ConnectorTypeSMTP:
		receiver.EmailConfigs = []map[string]any{cfg}
	case store.ConnectorTypeMSTeamsV2:
		receiver.MSTeamsV2Config = []map[string]any{cfg}
	case store.ConnectorTypeOpsgenie:
		receiver.OpsgenieConfigs = []map[string]any{cfg}
	case store.ConnectorTypePagerDuty:
		receiver.PagerDutyConfig = []map[string]any{cfg}
	case store.ConnectorTypePushover:
		receiver.PushoverConfigs = []map[string]any{cfg}
	case store.ConnectorTypeRocketChat:
		receiver.RocketChatCfg = []map[string]any{cfg}
	case store.ConnectorTypeSlack:
		receiver.SlackConfigs = []map[string]any{cfg}
	case store.ConnectorTypeSNS:
		receiver.SNSConfigs = []map[string]any{cfg}
	case store.ConnectorTypeTelegram:
		receiver.TelegramConfigs = []map[string]any{cfg}
	case store.ConnectorTypeVictorOps:
		receiver.VictorOpsConfig = []map[string]any{cfg}
	case store.ConnectorTypeWebex:
		receiver.WebexConfigs = []map[string]any{cfg}
	case store.ConnectorTypeWebhook:
		receiver.WebhookConfigs = []map[string]any{cfg}
	case store.ConnectorTypeWeChat:
		receiver.WeChatConfigs = []map[string]any{cfg}
	default:
		return fmt.Errorf("unsupported receiver type: %s", connectorType)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	// Alertmanager sidecar/container must be able to read the rendered config file.
	// Use world-readable mode for this non-executable config payload.
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func canonicalEmailSet(emails []string) (string, []string) {
	if len(emails) == 0 {
		return "", nil
	}
	seen := make(map[string]struct{}, len(emails))
	out := make([]string, 0, len(emails))
	for _, email := range emails {
		value := strings.ToLower(strings.TrimSpace(email))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return "", nil
	}
	sort.Strings(out)
	return strings.Join(out, ","), out
}

func shortSHA1(input string) string {
	sum := sha1.Sum([]byte(input))
	return hex.EncodeToString(sum[:])[:12]
}

func smtpToAlertmanagerTLSConfig(cfg *SMTPConfig) *alertmanagerTLSConfig {
	if cfg == nil {
		return nil
	}
	tlsCfg := &alertmanagerTLSConfig{}
	if cfg.CAFile != "" {
		tlsCfg.CAFile = cfg.CAFile
	}
	if cfg.ServerName != "" {
		tlsCfg.ServerName = cfg.ServerName
	}
	if cfg.VerifyMode == "none" {
		tlsCfg.InsecureSkipVerify = true
	}
	if tlsCfg.CAFile == "" && tlsCfg.ServerName == "" && !tlsCfg.InsecureSkipVerify {
		return nil
	}
	return tlsCfg
}

func smtpFromAddress(cfg *SMTPConfig) string {
	if cfg == nil {
		return ""
	}
	email := sanitizeSMTPHeaderValue(cfg.FromEmail)
	name := sanitizeSMTPHeaderValue(cfg.FromName)
	if email == "" {
		return ""
	}
	if name == "" {
		return email
	}
	return fmt.Sprintf("%s <%s>", name, email)
}

func sanitizeSMTPHeaderValue(value string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(strings.TrimSpace(value))
}

func markJobDoneWithLog(st store.Store, jobID uuid.UUID, logger *slog.Logger, msg string) error {
	if strings.TrimSpace(msg) != "" {
		logger.Warn(msg, "job_id", jobID)
	}
	return st.MarkAlertDispatchJobDone(jobID)
}

func handleDispatchFailure(st store.Store, cfg AlertmanagerIntegrationConfig, job store.AlertDispatchJob, err error, logger *slog.Logger) error {
	now := time.Now().UTC()
	retryable := isRetryableAlertmanagerError(err)
	errorCode := "dispatch_error"
	var statusErr HTTPStatusError
	if errors.As(err, &statusErr) {
		errorCode = fmt.Sprintf("http_%d", statusErr.StatusCode)
	}
	if !retryable || job.AttemptCount >= cfg.RetryMaxAttempts || now.After(job.CreatedAt.Add(cfg.RetryMaxWindow)) {
		markErr := st.MarkAlertDispatchJobDead(job.ID, errorCode, err.Error())
		if markErr != nil {
			return markErr
		}
		logger.Error("dispatch job marked dead", "job_id", job.ID, "attempt", job.AttemptCount, "error", err)
		return nil
	}
	next := now.Add(backoffForAttempt(job.AttemptCount))
	markErr := st.MarkAlertDispatchJobRetry(job.ID, next, errorCode, err.Error())
	if markErr != nil {
		return markErr
	}
	logger.Warn("dispatch job scheduled for retry", "job_id", job.ID, "attempt", job.AttemptCount, "next_attempt_at", next, "error", err)
	return nil
}

func backoffForAttempt(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := 5 * time.Second
	max := 15 * time.Minute
	backoff := base * time.Duration(1<<(attempt-1))
	if backoff > max {
		return max
	}
	return backoff
}

func isRetryableAlertmanagerError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var statusErr HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == 429 || statusErr.StatusCode >= 500
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return true
	}
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "reset by peer") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "no such host")
}
