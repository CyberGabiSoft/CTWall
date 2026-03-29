package router

import (
	"fmt"
	"net/http"

	"backend/internal/api/handlers"
	"backend/internal/api/middleware"
	"backend/internal/audit"
	"backend/internal/config"
	"backend/internal/core/auth"
	"backend/internal/core/componentanalysis"
	"backend/internal/core/malware"
	"backend/internal/store"
)

// Config defines router configuration.
type Config struct {
	Auth                       middleware.AuthConfig
	AuditWriter                *audit.Writer
	Malware                    *malware.OSVSyncService
	IngestWorkers              int
	ComponentAnalysisService   *componentanalysis.Service
	ComponentAnalysisScheduler *componentanalysis.Scheduler
	RuntimeConfig              config.Config
	RuntimeConfigPath          string
	RuntimeConfigSources       map[string]string
}

type routeSpec struct {
	pattern     string
	component   string
	handler     http.HandlerFunc
	roles       []auth.Role
	requireJSON bool
}

// NewRouter initializes the HTTP router with all application routes.
func NewRouter(memStore store.Store, cfg Config) (*http.ServeMux, error) {
	mux := http.NewServeMux()

	authMiddleware, err := middleware.NewAuthMiddleware(memStore, cfg.Auth)
	if err != nil {
		return nil, err
	}
	require := func(roles ...auth.Role) func(http.HandlerFunc) http.HandlerFunc {
		return authMiddleware.RequireRoles(roles...)
	}
	limitJSON := middleware.WithBodyLimit(middleware.DefaultJSONBodyLimit)
	requireJSON := middleware.RequireJSONContentType()
	jsonHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return limitJSON(requireJSON(h))
	}
	register := routeRegistrar{
		mux:         mux,
		auditWriter: cfg.AuditWriter,
		require:     require,
		jsonHandler: jsonHandler,
		seen:        make(map[string]struct{}),
	}

	for _, spec := range buildRouteSpecs(memStore, cfg) {
		if err := register.mustHandle(spec); err != nil {
			return nil, err
		}
	}
	return mux, nil
}

type routeRegistrar struct {
	mux         *http.ServeMux
	auditWriter *audit.Writer
	require     func(...auth.Role) func(http.HandlerFunc) http.HandlerFunc
	jsonHandler func(http.HandlerFunc) http.HandlerFunc
	seen        map[string]struct{}
}

func (r *routeRegistrar) mustHandle(spec routeSpec) error {
	if _, exists := r.seen[spec.pattern]; exists {
		return fmt.Errorf("duplicate route registration: %s", spec.pattern)
	}
	r.seen[spec.pattern] = struct{}{}

	handler := spec.handler
	if spec.requireJSON {
		handler = r.jsonHandler(handler)
	}
	if len(spec.roles) > 0 {
		handler = r.require(spec.roles...)(handler)
	}
	handler = middleware.WithLogging(spec.component, r.auditWriter, handler)
	r.mux.HandleFunc(spec.pattern, handler)
	return nil
}

func buildRouteSpecs(memStore store.Store, cfg Config) []routeSpec {
	authHandlerCfg := handlers.AuthConfig{
		JWTSecret:         cfg.Auth.JWTSecret,
		JWTIssuer:         cfg.Auth.JWTIssuer,
		AccessTokenTTL:    cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL:   cfg.Auth.RefreshTokenTTL,
		CookieName:        cfg.Auth.CookieName,
		RefreshCookieName: cfg.Auth.RefreshCookieName,
		CookieSecure:      cfg.Auth.CookieSecure,
		AuditWriter:       cfg.AuditWriter,
	}
	allRoles := auth.AllRoles()

	routes := []routeSpec{
		// System routes
		{pattern: "GET /health", component: "handler.health", handler: handlers.HealthHandler},
		{pattern: "GET /api/v1/health", component: "handler.health", handler: handlers.HealthHandler},
		{pattern: "GET /docs", component: "handler.docs", handler: handlers.DocsHandler()},
		{pattern: "GET /api/v1/openapi.yaml", component: "handler.openapi", handler: handlers.OpenAPIHandler()},

		// Auth
		{pattern: "POST /api/v1/auth/login", component: "handler.auth.login", handler: handlers.AuthLoginHandler(memStore, authHandlerCfg), requireJSON: true},
		{pattern: "POST /api/v1/auth/refresh", component: "handler.auth.refresh", handler: handlers.AuthRefreshHandler(memStore, authHandlerCfg), requireJSON: true},
		{pattern: "POST /api/v1/auth/logout", component: "handler.auth.logout", handler: handlers.AuthLogoutHandler(memStore, authHandlerCfg), roles: allRoles},
		{pattern: "POST /api/v1/auth/change-password", component: "handler.auth.change_password", handler: handlers.AuthChangePasswordHandler(memStore, authHandlerCfg), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/auth/me", component: "handler.auth.me", handler: handlers.AuthMeHandler(), roles: allRoles},

		// Projects / workspace selection
		{pattern: "GET /api/v1/projects", component: "handler.projects.list", handler: handlers.ListProjectsHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/projects", component: "handler.projects.create", handler: handlers.CreateProjectHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "PUT /api/v1/projects/{projectId}", component: "handler.projects.update", handler: handlers.UpdateProjectHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "DELETE /api/v1/projects/{projectId}", component: "handler.projects.delete", handler: handlers.DeleteProjectHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "GET /api/v1/projects/{projectId}/members", component: "handler.projects.members.list", handler: handlers.ListProjectMembersHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/projects/{projectId}/members", component: "handler.projects.members.put", handler: handlers.ReplaceProjectMembersHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/me/project", component: "handler.projects.selected.get", handler: handlers.GetSelectedProjectHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/me/project", component: "handler.projects.selected.put", handler: handlers.SetSelectedProjectHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},

		// Dashboard / Posture overview (project-scoped)
		{pattern: "GET /api/v1/dashboard/overview", component: "handler.dashboard.overview", handler: handlers.DashboardOverviewHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/security/posture/overview", component: "handler.security.posture.overview", handler: handlers.SecurityPostureOverviewHandler(memStore), roles: allRoles},

		// Events (Important System Events)
		{pattern: "GET /api/v1/events/open-count", component: "handler.events.open_count", handler: handlers.EventsOpenCountHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/events", component: "handler.events.list", handler: handlers.ListEventsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/events/{eventKey}", component: "handler.events.get", handler: handlers.GetEventHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/events/{eventKey}/ack", component: "handler.events.ack", handler: handlers.AckEventHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}},

		// Alerts (Security -> Alerts)
		{pattern: "GET /api/v1/alert-groups", component: "handler.alert_groups.list", handler: handlers.ListAlertGroupsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/alert-groups/{id}", component: "handler.alert_groups.get", handler: handlers.GetAlertGroupHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/alert-groups/{id}/acknowledge", component: "handler.alert_groups.acknowledge", handler: handlers.AcknowledgeAlertGroupHandler(memStore, cfg.AuditWriter), roles: allRoles},
		{pattern: "POST /api/v1/alert-groups/{id}/close", component: "handler.alert_groups.close", handler: handlers.CloseAlertGroupHandler(memStore, cfg.AuditWriter), roles: allRoles},
		{pattern: "GET /api/v1/alert-occurrences", component: "handler.alert_occurrences.list", handler: handlers.ListAlertOccurrencesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/alerting/connectors", component: "handler.alerting.connectors.get", handler: handlers.GetAlertingConnectorsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/alerting/connectors/{type}", component: "handler.alerting.connectors.upsert", handler: handlers.UpsertAlertingConnectorHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/alerting/dedup-rules", component: "handler.alerting.dedup_rules.list", handler: handlers.ListAlertDedupRulesHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/alerting/dedup-rules", component: "handler.alerting.dedup_rules.put", handler: handlers.PutAlertDedupRulesHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/data/jira/metadata/projects", component: "handler.jira.metadata.projects", handler: handlers.GetJiraMetadataProjectsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/issue-types", component: "handler.jira.metadata.issue_types", handler: handlers.GetJiraMetadataIssueTypesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/components", component: "handler.jira.metadata.components", handler: handlers.GetJiraMetadataComponentsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/issues", component: "handler.jira.metadata.issues", handler: handlers.GetJiraMetadataIssuesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/priorities", component: "handler.jira.metadata.priorities", handler: handlers.GetJiraMetadataPrioritiesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/transitions", component: "handler.jira.metadata.transitions", handler: handlers.GetJiraMetadataTransitionsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/jira/metadata/issue-fields", component: "handler.jira.metadata.issue_fields", handler: handlers.GetJiraMetadataIssueFieldsHandler(memStore), roles: allRoles},

		// Ingest
		{
			pattern:   "POST /api/v1/ingest",
			component: "handler.ingest",
			handler: handlers.IngestHandler(memStore, handlers.IngestConfig{
				EnqueueWorkers:            cfg.IngestWorkers,
				ComponentAnalysisNotifier: cfg.ComponentAnalysisService,
			}),
			roles: allRoles,
		},
		{
			pattern:   "GET /api/v1/tests/{testId}/revisions/{revisionId}/depalert-verdict",
			component: "handler.depalert.revision_verdict",
			handler:   handlers.GetDepAlertRevisionVerdictHandler(memStore),
			roles:     allRoles,
		},

		// Search
		{pattern: "GET /api/v1/search", component: "handler.search", handler: handlers.SearchHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/graph/chain", component: "handler.data.graph.chain", handler: handlers.DataGraphChainHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/graph/component-details", component: "handler.data.graph.component_details", handler: handlers.DataGraphComponentDetailsHandler(memStore), roles: allRoles},

		// Groups
		{pattern: "GET /api/v1/groups", component: "handler.groups.list", handler: handlers.ListGroupsHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/groups", component: "handler.groups.create", handler: handlers.CreateGroupHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/groups/{groupId}/members", component: "handler.groups.members.list", handler: handlers.ListGroupMembersHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/groups/{groupId}/members", component: "handler.groups.members.put", handler: handlers.PutGroupMembersHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},

		// Products
		{pattern: "GET /api/v1/products", component: "handler.products.list", handler: handlers.ListProductsHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/products", component: "handler.products.create", handler: handlers.CreateProductHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/products/{productId}", component: "handler.products.get", handler: handlers.GetProductHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/products/{productId}/jira/settings", component: "handler.products.jira_settings.get", handler: handlers.GetProductJiraSettingsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/data/products/{productId}/jira/settings", component: "handler.products.jira_settings.put", handler: handlers.PutProductJiraSettingsHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/data/products/{productId}/jira/issues", component: "handler.products.jira_issues.list", handler: handlers.GetProductJiraIssuesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/products/{productId}/jira/deliveries", component: "handler.products.jira_deliveries.list", handler: handlers.GetProductJiraDeliveriesHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/data/products/{productId}/jira/retry", component: "handler.products.jira_retry.post", handler: handlers.PostProductJiraRetryHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/products/{productId}/access", component: "handler.products.access.get", handler: handlers.GetProductAccessHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/products/{productId}/access", component: "handler.products.access.put", handler: handlers.PutProductAccessHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "DELETE /api/v1/products/{productId}", component: "handler.products.delete", handler: handlers.DeleteProductHandler(memStore), roles: allRoles},

		// Scopes
		{pattern: "GET /api/v1/scopes", component: "handler.scopes.list_all", handler: handlers.ListAllScopesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/products/{productId}/scopes", component: "handler.scopes.list", handler: handlers.ListScopesHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/products/{productId}/scopes", component: "handler.scopes.create", handler: handlers.CreateScopeHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/data/scopes/{scopeId}/jira/settings", component: "handler.scopes.jira_settings.get", handler: handlers.GetScopeJiraSettingsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/data/scopes/{scopeId}/jira/settings", component: "handler.scopes.jira_settings.put", handler: handlers.PutScopeJiraSettingsHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/data/scopes/{scopeId}/jira/issues", component: "handler.scopes.jira_issues.list", handler: handlers.GetScopeJiraIssuesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/scopes/{scopeId}/jira/deliveries", component: "handler.scopes.jira_deliveries.list", handler: handlers.GetScopeJiraDeliveriesHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/data/scopes/{scopeId}/jira/retry", component: "handler.scopes.jira_retry.post", handler: handlers.PostScopeJiraRetryHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "DELETE /api/v1/scopes/{scopeId}", component: "handler.scopes.delete", handler: handlers.DeleteScopeHandler(memStore), roles: allRoles},

		// Tests + revisions
		{pattern: "GET /api/v1/tests", component: "handler.tests.list_all", handler: handlers.ListAllTestsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/scopes/{scopeId}/tests", component: "handler.tests.list", handler: handlers.ListTestsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/tests/{testId}/jira/settings", component: "handler.tests.jira_settings.get", handler: handlers.GetTestJiraSettingsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/data/tests/{testId}/jira/settings", component: "handler.tests.jira_settings.put", handler: handlers.PutTestJiraSettingsHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/data/tests/{testId}/jira/effective-settings", component: "handler.tests.jira_settings.effective", handler: handlers.GetTestEffectiveJiraSettingsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/tests/{testId}/jira/issues", component: "handler.tests.jira_issues.list", handler: handlers.GetTestJiraIssuesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/data/tests/{testId}/jira/deliveries", component: "handler.tests.jira_deliveries.list", handler: handlers.GetTestJiraDeliveriesHandler(memStore), roles: allRoles},
		{pattern: "POST /api/v1/data/tests/{testId}/jira/retry", component: "handler.tests.jira_retry.post", handler: handlers.PostTestJiraRetryHandler(memStore), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/tests/{testId}/revisions", component: "handler.revisions.list", handler: handlers.ListRevisionsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/revisions/last-changes", component: "handler.revision_changes.list", handler: handlers.ListTestRevisionLastChangesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/revisions/{revisionId}/changes", component: "handler.revision_changes.details", handler: handlers.ListTestRevisionChangesHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/revisions/{revisionId}/changes/summary", component: "handler.revision_changes.summary", handler: handlers.GetTestRevisionChangesSummaryHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/components", component: "handler.components.list", handler: handlers.ListComponentsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/components/count", component: "handler.components.count", handler: handlers.CountComponentsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/components/{componentId}", component: "handler.components.get", handler: handlers.GetComponentHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/search/component-occurrences", component: "handler.search.component_occurrences", handler: handlers.SearchComponentOccurrencesHandler(memStore), roles: allRoles},

		// Explorer
		{pattern: "GET /api/v1/tests/{testId}/component-analysis/explorer/summary", component: "handler.test_revision_malware_summary.get", handler: handlers.GetActiveTestRevisionMalwareSummaryHandler(memStore, cfg.ComponentAnalysisService), roles: allRoles},
		{pattern: "POST /api/v1/component-analysis/explorer/summary/recompute", component: "handler.test_revision_malware_summary.recompute_all", handler: handlers.RecomputeAllActiveTestRevisionMalwareSummariesHandler(memStore, cfg.ComponentAnalysisService, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}},
		{pattern: "GET /api/v1/component-analysis/explorer/summary/recompute-history", component: "handler.test_revision_malware_summary.recompute_history", handler: handlers.ListMalwareSummaryRecomputeHistoryHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/tests/{testId}/component-analysis/explorer/findings", component: "handler.test_component_analysis.findings.list", handler: handlers.ListTestComponentAnalysisMalwareFindingsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/tests/{testId}/component-analysis/explorer/findings/triage", component: "handler.explorer.findings.triage.upsert", handler: handlers.UpsertTestComponentMalwareFindingTriageHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "DELETE /api/v1/tests/{testId}", component: "handler.tests.delete", handler: handlers.DeleteTestHandler(memStore), roles: allRoles},

		// SBOMs
		{pattern: "GET /api/v1/sboms", component: "handler.sboms.list", handler: handlers.ListSbomsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/sboms/{revisionId}/download", component: "handler.sboms.download", handler: handlers.DownloadSbomHandler(memStore), roles: allRoles},
		{pattern: "DELETE /api/v1/sboms/{revisionId}", component: "handler.sboms.delete", handler: handlers.DeleteSbomHandler(memStore), roles: []auth.Role{auth.RoleAdmin}},

		// Users
		{pattern: "GET /api/v1/users", component: "handler.users.list", handler: handlers.ListUsersHandler(memStore), roles: []auth.Role{auth.RoleAdmin}},
		{pattern: "POST /api/v1/users", component: "handler.users.create", handler: handlers.CreateUserHandler(memStore), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "PATCH /api/v1/users/{userId}", component: "handler.users.update", handler: handlers.UpdateUserHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "POST /api/v1/users/{userId}/password", component: "handler.users.password_reset", handler: handlers.ResetUserPasswordHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "POST /api/v1/users/{userId}/tokens", component: "handler.users.tokens.create", handler: handlers.CreateUserTokenHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "DELETE /api/v1/users/{userId}", component: "handler.users.delete", handler: handlers.DeleteUserHandler(memStore), roles: []auth.Role{auth.RoleAdmin}},

		// Settings (admin)
		{pattern: "GET /api/v1/admin/settings/general", component: "handler.settings.general", handler: handlers.AdminSettingsGeneralHandler(cfg.RuntimeConfig, cfg.RuntimeConfigPath, cfg.RuntimeConfigSources), roles: []auth.Role{auth.RoleAdmin}},
		{pattern: "GET /api/v1/admin/connectors", component: "handler.settings.connectors.list", handler: handlers.ListAdminConnectorsHandler(memStore), roles: allRoles},
		{pattern: "PUT /api/v1/admin/connectors/{type}", component: "handler.settings.connectors.upsert", handler: handlers.UpsertAdminConnectorHandler(memStore, cfg.AuditWriter), roles: allRoles, requireJSON: true},
		{pattern: "POST /api/v1/admin/connectors/{type}/test", component: "handler.settings.connectors.test", handler: handlers.TestAdminConnectorHandler(memStore, cfg.AuditWriter), roles: allRoles},

		// Malware sources/results
		{pattern: "GET /api/v1/explorer/sources", component: "handler.malware.sources.list", handler: handlers.ListMalwareSourcesHandler(memStore), roles: allRoles},
		{pattern: "PATCH /api/v1/explorer/sources/{sourceId}", component: "handler.malware.sources.update", handler: handlers.UpdateMalwareSourceHandler(memStore), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
		{pattern: "POST /api/v1/explorer/sources/{sourceId}/results/recompute", component: "handler.malware.sources.results.recompute", handler: handlers.RecomputeMalwareSourceResultsHandler(memStore, cfg.AuditWriter), roles: []auth.Role{auth.RoleAdmin}},
		{pattern: "GET /api/v1/explorer/sources/{sourceId}/results/recompute-history", component: "handler.malware.sources.results.recompute_history", handler: handlers.ListMalwareSourceResultsRecomputeHistoryHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/explorer/sources/{sourceId}/sync-history", component: "handler.malware.sources.sync_history", handler: handlers.ListMalwareSourceSyncHistoryHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/explorer/sources/{sourceId}/sync-history/{syncId}/errors", component: "handler.malware.sources.sync_errors", handler: handlers.ListMalwareSourceSyncErrorsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/explorer/results", component: "handler.malware.results.list", handler: handlers.ListAnalysisResultsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/explorer/findings", component: "handler.malware.findings.list", handler: handlers.ListScanComponentResultsHandler(memStore), roles: allRoles},

		// Component analysis (malware mapping)
		{pattern: "POST /api/v1/component-analysis/explorer/queue", component: "handler.component_analysis.queue.enqueue", handler: handlers.EnqueueComponentAnalysisHandler(memStore, cfg.ComponentAnalysisService), roles: allRoles, requireJSON: true},
		{pattern: "GET /api/v1/component-analysis/explorer/queue", component: "handler.component_analysis.queue.list", handler: handlers.ListComponentAnalysisQueueHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/component-analysis/explorer/queue/{runId}", component: "handler.component_analysis.queue.get", handler: handlers.GetComponentAnalysisQueueHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/component-analysis/explorer/findings", component: "handler.component_analysis.findings.list", handler: handlers.ListComponentAnalysisFindingsHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/component-analysis/explorer/findings/{findingId}", component: "handler.component_analysis.findings.get", handler: handlers.GetComponentAnalysisFindingHandler(memStore), roles: allRoles},
		{pattern: "GET /api/v1/component-analysis/explorer/schedule", component: "handler.component_analysis.schedule.get", handler: handlers.GetComponentAnalysisMalwareScheduleHandler(memStore), roles: []auth.Role{auth.RoleAdmin}},
		{pattern: "PATCH /api/v1/component-analysis/explorer/schedule", component: "handler.component_analysis.schedule.patch", handler: handlers.UpdateComponentAnalysisMalwareScheduleHandler(memStore, cfg.ComponentAnalysisService, cfg.ComponentAnalysisScheduler), roles: []auth.Role{auth.RoleAdmin}, requireJSON: true},
	}

	if cfg.Malware != nil {
		routes = append(routes,
			routeSpec{pattern: "POST /api/v1/explorer/osv/download_all", component: "handler.malware.osv.download_all", handler: handlers.DownloadOSVAllHandler(cfg.Malware), roles: []auth.Role{auth.RoleAdmin}},
			routeSpec{pattern: "POST /api/v1/explorer/osv/download_latest", component: "handler.malware.osv.download_latest", handler: handlers.DownloadOSVLatestHandler(cfg.Malware), roles: []auth.Role{auth.RoleAdmin}},
		)
	}

	return routes
}
