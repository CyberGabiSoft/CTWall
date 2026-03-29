package store

import (
	"encoding/json"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

// Store defines the storage contract for handlers.
type Store interface {
	Close() error

	GetUserByEmail(email string) (*UserCredentials, error)
	GetUserByID(id uuid.UUID) (*models.User, error)
	GetAPITokenByHash(hash string) (*APIToken, *models.User, error)
	UpdateAPITokenLastUsed(id uuid.UUID) error
	CreateAuditLog(entry AuditLogEntry) error
	ListAuditLogs(entityType string, entityID *uuid.UUID, actionPrefix string, limit, offset int) ([]models.AuditLog, error)
	ListAuditLogsExcludingAction(entityType string, entityID *uuid.UUID, actionPrefix string, excludedAction string, limit, offset int) ([]models.AuditLog, error)
	ListAuditLogsByActionAndDetail(entityType string, entityID *uuid.UUID, action string, detailsKey string, detailsValue string, limit, offset int) ([]models.AuditLog, error)
	CountOpenEvents(q EventsQuery) (int, error)
	ListEvents(q EventsQuery) ([]EventAggregate, int, error)
	GetEvent(eventKey string, q EventsQuery, occurrencesLimit int) (*EventAggregate, []models.AuditLog, error)
	CreateUser(email, passwordHash, role, accountType string, profile ...string) (*models.User, error)
	UpdateUser(id uuid.UUID, role, accountType string, profile ...string) (*models.User, error)
	UpdateUserPassword(userID uuid.UUID, passwordHash string) error
	CreateAPIToken(userID uuid.UUID, name, tokenHash string, expiresAt *time.Time) (*APIToken, error)
	CreateRefreshToken(userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, error)
	CreateRefreshTokenAndRevokeOthers(userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, error)
	RotateRefreshToken(currentHash, newHash string, newExpiresAt time.Time, userAgent, ipAddress string) (*RefreshToken, *models.User, error)
	RevokeRefreshToken(tokenHash string) error
	RevokeRefreshTokensForUser(userID uuid.UUID) error
	ListProjectsForUser(userID uuid.UUID, includeAll bool) ([]models.Project, error)
	CreateProject(name, description string, createdBy *uuid.UUID) (*models.Project, error)
	UpdateProject(id uuid.UUID, name, description string) (*models.Project, error)
	GetProject(id uuid.UUID) (*models.Project, error)
	DeleteProject(id uuid.UUID) (*models.Project, []models.Product, error)
	GetProjectRole(userID, projectID uuid.UUID) (string, error)
	ListProjectMembers(projectID uuid.UUID) ([]models.ProjectMember, error)
	ReplaceProjectMembers(projectID uuid.UUID, members []ProjectMemberAssignment, createdBy *uuid.UUID) error
	GetSelectedProjectID(userID uuid.UUID) (*uuid.UUID, error)
	SetSelectedProjectID(userID, projectID uuid.UUID) error
	UserHasProjectAccess(userID, projectID uuid.UUID, includeAll bool) (bool, error)
	EnsureUserSettings(userID uuid.UUID) error
	GetDashboardOverview(q DashboardOverviewQuery) (*DashboardOverview, error)
	GetSecurityPostureOverview(q SecurityPostureOverviewQuery) (*SecurityPostureOverview, error)

	ListGroupsByProject(projectID uuid.UUID) ([]models.UserGroup, error)
	CreateGroupInProject(projectID uuid.UUID, name, description string, createdBy uuid.UUID) (*models.UserGroup, error)
	ListGroupMembers(projectID, groupID uuid.UUID) ([]models.UserGroupMember, error)
	GetGroupMemberRole(projectID, groupID, userID uuid.UUID) (string, error)
	ReplaceGroupMembers(projectID, groupID uuid.UUID, members []GroupMemberAssignment, createdBy uuid.UUID) error
	ListGlobalConnectorConfigs() ([]ConnectorConfig, error)
	GetGlobalConnectorConfig(connectorType ConnectorType) (*ConnectorConfig, error)
	UpsertGlobalConnectorConfig(connectorType ConnectorType, configJSON json.RawMessage, isEnabled bool) (*ConnectorConfig, error)
	UpdateGlobalConnectorTestStatus(connectorType ConnectorType, status ConnectorTestStatus, message string, testedAt time.Time) (*ConnectorConfig, error)
	ListProjectConnectorConfigs(projectID uuid.UUID) ([]ConnectorConfig, error)
	GetProjectConnectorConfig(projectID uuid.UUID, connectorType ConnectorType) (*ConnectorConfig, error)
	UpsertProjectConnectorConfig(projectID uuid.UUID, connectorType ConnectorType, configJSON json.RawMessage, isEnabled bool) (*ConnectorConfig, error)
	UpdateProjectConnectorTestStatus(projectID uuid.UUID, connectorType ConnectorType, status ConnectorTestStatus, message string, testedAt time.Time) (*ConnectorConfig, error)

	// Alerts (project-scoped).
	ListAlertGroups(q AlertGroupsQuery) ([]models.AlertGroup, int, error)
	GetAlertGroup(projectID, id uuid.UUID) (*models.AlertGroup, error)
	AcknowledgeAlertGroup(projectID, groupID, actorID uuid.UUID) error
	CloseAlertGroup(projectID, groupID, actorID uuid.UUID) error
	ListAlertOccurrences(q AlertOccurrencesQuery) ([]models.AlertOccurrence, int, error)
	GetAlertConnectorSettings(projectID uuid.UUID) ([]AlertConnectorSettings, error)
	UpsertAlertConnectorSettings(projectID uuid.UUID, connectorType ConnectorType, enabled bool, routes []AlertRouteRef) (*AlertConnectorSettings, error)
	SetAlertConnectorJiraDedupRule(projectID uuid.UUID, dedupRuleID *uuid.UUID) (*AlertConnectorSettings, error)
	ValidateAlertRouteTargets(projectID uuid.UUID, targetType AlertRouteTargetType, ids []uuid.UUID) error
	ListAlertDedupRules(projectID uuid.UUID, alertType string) ([]models.AlertDedupRule, error)
	GetAlertDedupRuleByID(projectID, ruleID uuid.UUID) (*models.AlertDedupRule, error)
	ReplaceAlertDedupRules(projectID uuid.UUID, alertType string, rules []AlertDedupRuleInput) ([]models.AlertDedupRule, error)
	ResolveAlertDedupRule(input AlertDedupRuleResolutionInput) (*models.AlertDedupRule, error)
	GetJiraEntitySettings(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID) (*JiraEntitySettings, error)
	UpsertJiraEntitySettings(input JiraEntitySettingsUpsertInput) (*JiraEntitySettings, error)
	ResolveEffectiveJiraSettings(input JiraEffectiveSettingsResolveInput) (*JiraEffectiveSettings, error)
	ListOpenJiraIssueMappings(projectID, alertGroupID uuid.UUID, dedupRuleID *uuid.UUID) ([]JiraIssueMapping, error)
	GetLatestJiraIssueMappingForComponent(projectID, testID uuid.UUID, componentPURL string) (*JiraIssueMapping, error)
	ListJiraIssueMappingsByEntity(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID, filter JiraIssueMappingsListFilter) ([]JiraIssueMapping, int, error)
	UpsertJiraIssueMapping(input JiraIssueMappingUpsertInput) (*JiraIssueMapping, error)
	InsertJiraDeliveryAttempt(input JiraDeliveryAttemptInput) error
	ListJiraDeliveryAttemptsByEntity(projectID uuid.UUID, configLevel JiraConfigLevel, configTargetID uuid.UUID, limit, offset int) ([]JiraDeliveryAttempt, int, error)
	GetJiraMetadataCache(projectID uuid.UUID, baseURLHash string, metadataType JiraMetadataType, metadataScopeKey string) (*JiraMetadataCacheEntry, error)
	UpsertJiraMetadataCache(input JiraMetadataCacheUpsertInput) (*JiraMetadataCacheEntry, error)
	ReconcileMalwareAlertGroup(projectID uuid.UUID, malwarePURL string, actorID *uuid.UUID) error
	ReconcileMalwareAlertGroupsForProject(projectID uuid.UUID, actorID *uuid.UUID) (int, error)
	EnqueueAlertDispatchJob(input AlertDispatchEnqueueInput) (*AlertDispatchJob, error)
	ClaimAlertDispatchJobs(messageType AlertDispatchMessageType, limit int, lockedBy string) ([]AlertDispatchJob, error)
	MarkAlertDispatchJobDone(id uuid.UUID) error
	MarkAlertDispatchJobRetry(id uuid.UUID, nextAttemptAt time.Time, errorCode, errorMessage string) error
	MarkAlertDispatchJobDead(id uuid.UUID, errorCode, errorMessage string) error
	RequeueStaleAlertDispatchJobs(staleAfter time.Duration, limit int) (int, error)
	UpdateAlertGroupLastNotifiedAt(projectID, groupID uuid.UUID, notifiedAt time.Time) error
	ListEnabledAlertProjects(connectorType ConnectorType) ([]uuid.UUID, error)
	ListProjectAdminEmails(projectID uuid.UUID) ([]string, error)
	GetLatestAlertOccurrenceContext(projectID, groupID uuid.UUID) (*AlertOccurrenceContext, error)
	ListAlertGroupComponentContexts(projectID, groupID uuid.UUID) ([]AlertGroupComponentContext, error)
	IsComponentMalwareActiveInTest(projectID, testID uuid.UUID, componentPURL string) (bool, error)
	ListOpenAlertGroupsForHeartbeat(limit int, olderThan time.Duration) ([]models.AlertGroup, error)

	EnsureProduct(name, description string) (*models.Product, bool, error)
	EnsureProductInProject(projectID uuid.UUID, name, description string) (*models.Product, bool, error)
	CreateProduct(name, description string) (*models.Product, error)
	CreateProductInProject(projectID uuid.UUID, name, description string) (*models.Product, error)
	CreateProductWithOwnerGroup(projectID uuid.UUID, name, description string, ownerGroupID *uuid.UUID, actorID uuid.UUID) (*models.Product, error)
	GetEffectiveProductRole(projectID, productID, userID uuid.UUID) (string, error)
	ListProductGroupGrants(projectID, productID uuid.UUID) (*models.Product, []models.ProductGroupGrant, error)
	ReplaceProductGroupGrants(projectID, productID uuid.UUID, grants []ProductGroupGrantAssignment, createdBy uuid.UUID) error
	GetProduct(id uuid.UUID) (*models.Product, error)
	GetProductInProject(projectID, productID uuid.UUID) (*models.Product, error)
	ListProducts() ([]models.Product, error)
	ListProductsByProject(projectID uuid.UUID) ([]models.Product, error)
	DeleteProduct(id uuid.UUID) error

	EnsureScope(productID uuid.UUID, name, description string) (*models.Scope, bool, error)
	CreateScope(productID uuid.UUID, name, description string) (*models.Scope, error)
	GetScope(id uuid.UUID) (*models.Scope, error)
	GetScopeInProject(projectID, scopeID uuid.UUID) (*models.Scope, error)
	ListScopes(productID uuid.UUID) ([]models.Scope, error)
	DeleteScope(id uuid.UUID) error

	EnsureTest(scopeID uuid.UUID, name, sbomStandard, sbomSpecVersion string) (*models.Test, bool, error)
	GetTest(id uuid.UUID) (*models.Test, error)
	GetTestInProject(projectID, testID uuid.UUID) (*models.Test, error)
	ListTests(scopeID uuid.UUID) ([]models.Test, error)
	DeleteTest(id uuid.UUID) error

	AddRevision(testID uuid.UUID, input RevisionInput) (*models.TestRevision, error)
	ListRevisions(testID uuid.UUID) ([]models.TestRevision, error)
	GetRevision(id uuid.UUID) (*models.TestRevision, error)
	GetRevisionInProject(projectID, revisionID uuid.UUID) (*models.TestRevision, error)
	DeleteRevision(id uuid.UUID) error
	DeleteRevisionInProject(projectID, revisionID uuid.UUID) error
	ListAllRevisions() ([]models.TestRevision, error)
	ListComponents(testID uuid.UUID) ([]models.Component, error)
	ListComponentsPage(testID uuid.UUID, filter ComponentListFilter, sort ComponentListSort, limit, offset int) ([]models.Component, error)
	CountComponents(testID uuid.UUID) (int, error)
	GetComponent(testID, componentID uuid.UUID) (*models.Component, error)
	GetDataGraphComponentByPURL(projectID, testID, revisionID uuid.UUID, componentPURL string) (*DataGraphComponentRecord, error)
	ListDataGraphProjectOccurrencesByPURL(projectID uuid.UUID, componentPURL string, limit int) ([]DataGraphComponentOccurrence, error)
	ListDataGraphRevisionComponentFindings(projectID, testID, revisionID uuid.UUID, componentPURL string, limit int) ([]DataGraphComponentFinding, error)
	ListDataGraphRevisionMalwareCounts(projectID, testID, revisionID uuid.UUID, componentPURLs []string) (map[string]int, error)
	SearchComponentOccurrencesPage(query string, limit, offset int) ([]ComponentOccurrence, int, error)
	SearchComponentOccurrencesPageByProject(projectID uuid.UUID, query string, limit, offset int) ([]ComponentOccurrence, int, error)

	CreateIngestJob(input IngestRequest) (*IngestJob, error)
	UpdateIngestJobStatus(id uuid.UUID, status string, errorMessage string) error
	UpdateIngestJobStage(id uuid.UUID, stage string, errorMessage string) error

	StoreSbom(sha string, data []byte, format string, contentType string, isGzip bool) (*SbomObject, error)
	GetSbomBySHA(sha string) (*SbomObject, error)

	ListAllScopes() ([]models.Scope, error)
	ListAllScopesByProject(projectID uuid.UUID) ([]models.Scope, error)
	ListAllTests() ([]models.Test, error)
	ListAllTestsByProject(projectID uuid.UUID) ([]models.Test, error)

	ListUsers() ([]models.User, error)
	DeleteUser(id uuid.UUID) error

	CreateScanMalwareSource(name, sourceType, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error)
	ListScanMalwareSources() ([]*models.ScanMalwareSource, error)
	GetScanMalwareSource(id uuid.UUID) (*models.ScanMalwareSource, error)
	GetScanMalwareSourceByName(name, sourceType string) (*models.ScanMalwareSource, error)
	EnsureScanMalwareSource(name, sourceType, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error)
	UpdateScanMalwareSource(id uuid.UUID, baseURL string, config json.RawMessage, isActive bool) (*models.ScanMalwareSource, error)

	CreateScanner(sourceID uuid.UUID, name, scannerType, version, resultsPath string, config json.RawMessage) (*models.Scanner, error)
	ListScanners() ([]*models.Scanner, error)
	EnsureScanner(sourceID uuid.UUID, name, scannerType, version, resultsPath string, config json.RawMessage) (*models.Scanner, error)

	EnqueueAnalysis(componentPURL string, scannerID uuid.UUID) (*models.AnalysisQueueItem, error)
	UpsertAnalysisQueue(componentPURL string, scannerID uuid.UUID, status string) (*models.AnalysisQueueItem, error)
	UpdateAnalysisQueueStatus(id uuid.UUID, status string) error

	CreateAnalysisResult(input AnalysisResultInput) (*models.AnalysisResult, error)
	UpsertAnalysisResultFromFindings(componentPURL, componentHash, summary string) (*models.AnalysisResult, error)
	ListAnalysisResults(componentPURL string) ([]models.AnalysisResult, error)
	RecomputeAnalysisResultsForSource(sourceID uuid.UUID) (int, error)

	CreateScanComponentResult(input ScanComponentResultInput) (*models.ScanComponentResult, error)
	UpsertScanComponentResult(input ScanComponentResultInput) (*models.ScanComponentResult, error)
	ListScanComponentResults(componentPURL string, sourceID *uuid.UUID, limit, offset int) ([]models.ScanComponentResult, error)
	GetLatestScanComponentResultTimestamp(sourceID uuid.UUID) (*time.Time, error)
	PruneScanComponentResultsForSource(sourceID uuid.UUID, keepResultFilenames []string) (deleted int, affectedComponentPURLs []string, err error)
	RepairAnalysisResults(componentPURLs []string) error

	EnqueueComponentAnalysis(componentPURL, reason string, scheduledFor *time.Time) (*models.ComponentAnalysisQueueItem, error)
	EnqueueComponentAnalysisBatch(componentPURLs []string, reason string, scheduledFor *time.Time) (int, error)
	EnqueueStaleComponentAnalysis(reason string, scheduledFor *time.Time, limit int) (int, error)
	GetComponentAnalysisMalwareSchedule() (*models.ComponentAnalysisMalwareSchedule, error)
	UpdateComponentAnalysisMalwareSchedule(enabled bool, intervalSeconds int) (*models.ComponentAnalysisMalwareSchedule, error)
	ClaimComponentAnalysisJobs(limit int, lockedBy string) ([]models.ComponentAnalysisQueueItem, error)
	UpdateComponentAnalysisQueueStatus(id uuid.UUID, status, lastError string) error
	ListComponentAnalysisQueue(filter ComponentAnalysisQueueFilter) ([]models.ComponentAnalysisQueueItem, error)
	GetComponentAnalysisQueueItem(id uuid.UUID) (*models.ComponentAnalysisQueueItem, error)

	UpsertComponentAnalysisFinding(input ComponentAnalysisFindingInput) (*models.ComponentAnalysisFinding, error)
	ListComponentAnalysisFindings(componentPURL string) ([]models.ComponentAnalysisFinding, error)
	ListActiveTestComponentAnalysisMalwareFindings(testID uuid.UUID, limit, offset int) ([]models.ComponentAnalysisFinding, error)
	GetComponentAnalysisFinding(id uuid.UUID) (*models.ComponentAnalysisFinding, error)
	UpsertComponentAnalysisMalwareComponentState(componentPURL string, scannedAt time.Time, validUntil *time.Time) (*models.ComponentAnalysisMalwareComponentState, error)

	// Malware finding triage (per test).
	UpsertComponentMalwareFindingTriage(
		projectID, testID uuid.UUID,
		componentPURL, malwarePURL, status string,
		priority *string,
		reason *string,
		expiresAt *time.Time,
		authorID *uuid.UUID,
	) (*ComponentMalwareFindingTriageView, error)

	ListAnalysisResultsForComponentMatch(componentPURL string) ([]models.AnalysisResult, error)

	// Malware summary (materialized read model) for active test revisions.
	EnqueueTestRevisionMalwareSummary(revisionID uuid.UUID, reason string) (*models.TestRevisionMalwareSummaryQueueItem, error)
	EnqueueActiveTestRevisionMalwareSummaryByComponentPURL(componentPURL string, reason string) (int, error)
	EnqueueAllActiveTestRevisionMalwareSummary(reason string) (int, error)
	ClaimTestRevisionMalwareSummaryJobs(limit int, lockedBy string) ([]models.TestRevisionMalwareSummaryQueueItem, error)
	UpdateTestRevisionMalwareSummaryQueueStatus(id uuid.UUID, status, lastError string) error
	ComputeAndStoreTestRevisionMalwareSummary(revisionID uuid.UUID) (*models.TestRevisionMalwareSummary, error)
	GetActiveTestRevisionMalwareSummary(testID uuid.UUID) (*models.TestRevisionMalwareSummary, error)
	GetDepAlertRevisionVerdict(projectID, testID, revisionID uuid.UUID) (*DepAlertRevisionVerdict, error)

	// SBOM reimport diff (materialized read model + async queue).
	EnqueueTestRevisionFindingDiff(toRevisionID uuid.UUID, reason string) (*models.TestRevisionFindingDiffQueueItem, error)
	ClaimTestRevisionFindingDiffJobs(limit int, lockedBy string) ([]models.TestRevisionFindingDiffQueueItem, error)
	UpdateTestRevisionFindingDiffQueueStatus(id uuid.UUID, status, lastError string) error
	ComputeAndStoreTestRevisionFindingDiff(toRevisionID uuid.UUID) (*models.TestRevisionChangeSummary, error)
	ListTestRevisionLastChanges(testID uuid.UUID) ([]models.TestRevisionChangeSummary, error)
	GetTestRevisionChangeSummary(testID, revisionID uuid.UUID) (*models.TestRevisionChangeSummary, error)
	ListTestRevisionFindingDiffs(testID, revisionID uuid.UUID, diffTypes []string) ([]models.TestRevisionFindingDiff, error)
}
