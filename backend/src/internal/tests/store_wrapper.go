package tests

import (
	"encoding/json"
	"time"

	"backend/internal/models"
	"backend/internal/store"

	"github.com/google/uuid"
)

// StoreWrapper allows tests to override specific store operations.
type StoreWrapper struct {
	store.Store

	GetUserByEmailErr                 error
	GetUserByEmailCreds               *store.UserCredentials
	GetUserByIDErr                    error
	GetUserByIDUser                   *models.User
	GetAPITokenErr                    error
	GetAPIToken                       *store.APIToken
	GetAPITokenUser                   *models.User
	CreateRefreshTokenAndRevokeErr    error
	CreateRefreshTokenAndRevoke       *store.RefreshToken
	UpdateUserPasswordErr             error
	RevokeRefreshTokenErr             error
	RevokeRefreshTokensErr            error
	ListProductsErr                   error
	CreateProductErr                  error
	GetProductErr                     error
	GetProductMissing                 bool
	DeleteProductErr                  error
	ListScopesErr                     error
	CreateScopeErr                    error
	GetScopeErr                       error
	GetScopeMissing                   bool
	DeleteScopeErr                    error
	ListTestsErr                      error
	ListRevisionsErr                  error
	DeleteTestErr                     error
	EnsureProductErr                  error
	EnsureScopeErr                    error
	EnsureTestErr                     error
	GetTestErr                        error
	GetTestMissing                    bool
	GetRevisionErr                    error
	GetRevisionMissing                bool
	GetSbomErr                        error
	ListAllRevisionsErr               error
	DeleteRevisionErr                 error
	ListComponentsErr                 error
	ListComponentsItems               []models.Component
	ListComponentsPageErr             error
	ListComponentsPageItems           []models.Component
	CountComponentsErr                error
	CountComponentsValue              *int
	GetComponentErr                   error
	GetComponentItem                  *models.Component
	GetComponentMissing               bool
	UpdateProjectErr                  error
	GetProjectErrOverride             error
	GetProjectItem                    *models.Project
	ListProjectsForUserErr            error
	ListProjectsForUserItems          []models.Project
	GetProjectRoleErr                 error
	GetProjectRoleValue               string
	SearchComponentOccurrencesErr     error
	SearchComponentOccurrencesItems   []store.ComponentOccurrence
	SearchComponentOccurrencesTotal   int
	ListAllScopesErr                  error
	ListAllTestsErr                   error
	CreateIngestJobErr                error
	UpdateIngestStatusErr             error
	AddRevisionErr                    error
	ListUsersErr                      error
	DeleteUserErr                     error
	EnqueueComponentAnalysisErr       error
	EnqueueComponentAnalysisItem      *models.ComponentAnalysisQueueItem
	ListComponentAnalysisQueueErr     error
	ComponentAnalysisQueueItems       []models.ComponentAnalysisQueueItem
	GetComponentAnalysisQueueErr      error
	ComponentAnalysisQueueItem        *models.ComponentAnalysisQueueItem
	ListComponentAnalysisFindingsErr  error
	ComponentAnalysisFindings         []models.ComponentAnalysisFinding
	GetComponentAnalysisFindingErr    error
	ComponentAnalysisFinding          *models.ComponentAnalysisFinding
	ListGlobalConnectorConfigsErr     error
	GlobalConnectorConfigs            []store.ConnectorConfig
	ListGroupsErr                     error
	GroupsItems                       []models.UserGroup
	CreateGroupErr                    error
	CreatedGroup                      *models.UserGroup
	ListGroupMembersErr               error
	GroupMembersItems                 []models.UserGroupMember
	GetGroupMemberRoleErr             error
	GetGroupMemberRoleValue           string
	ReplaceGroupMembersErr            error
	CreateProductWithOwnerErr         error
	CreatedProductWithOwner           *models.Product
	GetEffectiveProductRoleErr        error
	GetEffectiveProductRoleValue      string
	ListProductGroupGrantsErr         error
	ListProductGroupGrantsProduct     *models.Product
	ListProductGroupGrantsItems       []models.ProductGroupGrant
	ReplaceProductGroupGrantsErr      error
	GetGlobalConnectorConfigErr       error
	GlobalConnectorConfig             *store.ConnectorConfig
	UpsertGlobalConnectorConfigErr    error
	UpdatedConnectorConfig            *store.ConnectorConfig
	UpdateConnectorTestStatusErr      error
	ConnectorTestStatusConfig         *store.ConnectorConfig
	ListProjectConnectorConfigsErr    error
	ProjectConnectorConfigs           []store.ConnectorConfig
	GetProjectConnectorConfigErr      error
	ProjectConnectorConfig            *store.ConnectorConfig
	UpsertProjectConnectorConfigErr   error
	UpdatedProjectConnectorConfig     *store.ConnectorConfig
	UpdateProjectConnectorTestErr     error
	ProjectConnectorTestStatusConfig  *store.ConnectorConfig
	EnqueueAlertDispatchErr           error
	EnqueueAlertDispatchItem          *store.AlertDispatchJob
	ListTestRevisionLastChangesErr    error
	ListTestRevisionLastChangesItems  []models.TestRevisionChangeSummary
	GetTestRevisionChangeSummaryErr   error
	GetTestRevisionChangeSummaryItem  *models.TestRevisionChangeSummary
	ListTestRevisionFindingDiffsErr   error
	ListTestRevisionFindingDiffsItems []models.TestRevisionFindingDiff
}

func (s StoreWrapper) GetUserByEmail(email string) (*store.UserCredentials, error) {
	if s.GetUserByEmailErr != nil {
		return nil, s.GetUserByEmailErr
	}
	if s.GetUserByEmailCreds != nil {
		return s.GetUserByEmailCreds, nil
	}
	return s.Store.GetUserByEmail(email)
}

func (s StoreWrapper) GetUserByID(id uuid.UUID) (*models.User, error) {
	if s.GetUserByIDErr != nil {
		return nil, s.GetUserByIDErr
	}
	if s.GetUserByIDUser != nil {
		return s.GetUserByIDUser, nil
	}
	return s.Store.GetUserByID(id)
}

func (s StoreWrapper) GetAPITokenByHash(hash string) (*store.APIToken, *models.User, error) {
	if s.GetAPITokenErr != nil {
		return nil, nil, s.GetAPITokenErr
	}
	if s.GetAPITokenUser != nil {
		return s.GetAPIToken, s.GetAPITokenUser, nil
	}
	return s.Store.GetAPITokenByHash(hash)
}

func (s StoreWrapper) CreateRefreshTokenAndRevokeOthers(userID uuid.UUID, tokenHash string, expiresAt time.Time, userAgent, ipAddress string) (*store.RefreshToken, error) {
	if s.CreateRefreshTokenAndRevokeErr != nil {
		return nil, s.CreateRefreshTokenAndRevokeErr
	}
	if s.CreateRefreshTokenAndRevoke != nil {
		return s.CreateRefreshTokenAndRevoke, nil
	}
	return s.Store.CreateRefreshTokenAndRevokeOthers(userID, tokenHash, expiresAt, userAgent, ipAddress)
}

func (s StoreWrapper) UpdateUserPassword(userID uuid.UUID, passwordHash string) error {
	if s.UpdateUserPasswordErr != nil {
		return s.UpdateUserPasswordErr
	}
	return s.Store.UpdateUserPassword(userID, passwordHash)
}

func (s StoreWrapper) RevokeRefreshToken(tokenHash string) error {
	if s.RevokeRefreshTokenErr != nil {
		return s.RevokeRefreshTokenErr
	}
	return s.Store.RevokeRefreshToken(tokenHash)
}

func (s StoreWrapper) RevokeRefreshTokensForUser(userID uuid.UUID) error {
	if s.RevokeRefreshTokensErr != nil {
		return s.RevokeRefreshTokensErr
	}
	return s.Store.RevokeRefreshTokensForUser(userID)
}

func (s StoreWrapper) ListProducts() ([]models.Product, error) {
	if s.ListProductsErr != nil {
		return nil, s.ListProductsErr
	}
	return s.Store.ListProducts()
}

func (s StoreWrapper) ListProductsByProject(projectID uuid.UUID) ([]models.Product, error) {
	return s.ListProducts()
}

func (s StoreWrapper) GetProjectRole(userID, projectID uuid.UUID) (string, error) {
	if s.GetProjectRoleErr != nil {
		return "", s.GetProjectRoleErr
	}
	if s.GetProjectRoleValue != "" {
		return s.GetProjectRoleValue, nil
	}
	return s.Store.GetProjectRole(userID, projectID)
}

func (s StoreWrapper) ListGroupsByProject(projectID uuid.UUID) ([]models.UserGroup, error) {
	if s.ListGroupsErr != nil {
		return nil, s.ListGroupsErr
	}
	if s.GroupsItems != nil {
		return s.GroupsItems, nil
	}
	return s.Store.ListGroupsByProject(projectID)
}

func (s StoreWrapper) CreateGroupInProject(projectID uuid.UUID, name, description string, createdBy uuid.UUID) (*models.UserGroup, error) {
	if s.CreateGroupErr != nil {
		return nil, s.CreateGroupErr
	}
	if s.CreatedGroup != nil {
		return s.CreatedGroup, nil
	}
	return s.Store.CreateGroupInProject(projectID, name, description, createdBy)
}

func (s StoreWrapper) ListGroupMembers(projectID, groupID uuid.UUID) ([]models.UserGroupMember, error) {
	if s.ListGroupMembersErr != nil {
		return nil, s.ListGroupMembersErr
	}
	if s.GroupMembersItems != nil {
		return s.GroupMembersItems, nil
	}
	return s.Store.ListGroupMembers(projectID, groupID)
}

func (s StoreWrapper) GetGroupMemberRole(projectID, groupID, userID uuid.UUID) (string, error) {
	if s.GetGroupMemberRoleErr != nil {
		return "", s.GetGroupMemberRoleErr
	}
	if s.GetGroupMemberRoleValue != "" {
		return s.GetGroupMemberRoleValue, nil
	}
	return s.Store.GetGroupMemberRole(projectID, groupID, userID)
}

func (s StoreWrapper) ReplaceGroupMembers(projectID, groupID uuid.UUID, members []store.GroupMemberAssignment, createdBy uuid.UUID) error {
	if s.ReplaceGroupMembersErr != nil {
		return s.ReplaceGroupMembersErr
	}
	return s.Store.ReplaceGroupMembers(projectID, groupID, members, createdBy)
}

func (s StoreWrapper) CreateProduct(name, description string) (*models.Product, error) {
	if s.CreateProductErr != nil {
		return nil, s.CreateProductErr
	}
	return s.Store.CreateProduct(name, description)
}

func (s StoreWrapper) CreateProductInProject(projectID uuid.UUID, name, description string) (*models.Product, error) {
	return s.CreateProduct(name, description)
}

func (s StoreWrapper) CreateProductWithOwnerGroup(projectID uuid.UUID, name, description string, ownerGroupID *uuid.UUID, actorID uuid.UUID) (*models.Product, error) {
	if s.CreateProductWithOwnerErr != nil {
		return nil, s.CreateProductWithOwnerErr
	}
	if s.CreatedProductWithOwner != nil {
		return s.CreatedProductWithOwner, nil
	}
	return s.Store.CreateProductWithOwnerGroup(projectID, name, description, ownerGroupID, actorID)
}

func (s StoreWrapper) GetEffectiveProductRole(projectID, productID, userID uuid.UUID) (string, error) {
	if s.GetEffectiveProductRoleErr != nil {
		return "", s.GetEffectiveProductRoleErr
	}
	if s.GetEffectiveProductRoleValue != "" {
		return s.GetEffectiveProductRoleValue, nil
	}
	return s.Store.GetEffectiveProductRole(projectID, productID, userID)
}

func (s StoreWrapper) ListProductGroupGrants(projectID, productID uuid.UUID) (*models.Product, []models.ProductGroupGrant, error) {
	if s.ListProductGroupGrantsErr != nil {
		return nil, nil, s.ListProductGroupGrantsErr
	}
	if s.ListProductGroupGrantsProduct != nil || s.ListProductGroupGrantsItems != nil {
		return s.ListProductGroupGrantsProduct, s.ListProductGroupGrantsItems, nil
	}
	return s.Store.ListProductGroupGrants(projectID, productID)
}

func (s StoreWrapper) ReplaceProductGroupGrants(projectID, productID uuid.UUID, grants []store.ProductGroupGrantAssignment, createdBy uuid.UUID) error {
	if s.ReplaceProductGroupGrantsErr != nil {
		return s.ReplaceProductGroupGrantsErr
	}
	return s.Store.ReplaceProductGroupGrants(projectID, productID, grants, createdBy)
}

func (s StoreWrapper) GetProduct(id uuid.UUID) (*models.Product, error) {
	if s.GetProductErr != nil {
		return nil, s.GetProductErr
	}
	if s.GetProductMissing {
		return nil, store.ErrNotFound
	}
	return s.Store.GetProduct(id)
}

func (s StoreWrapper) GetProductInProject(projectID, productID uuid.UUID) (*models.Product, error) {
	return s.GetProduct(productID)
}

func (s StoreWrapper) DeleteProduct(id uuid.UUID) error {
	if s.DeleteProductErr != nil {
		return s.DeleteProductErr
	}
	return s.Store.DeleteProduct(id)
}

func (s StoreWrapper) ListScopes(productID uuid.UUID) ([]models.Scope, error) {
	if s.ListScopesErr != nil {
		return nil, s.ListScopesErr
	}
	return s.Store.ListScopes(productID)
}

func (s StoreWrapper) CreateScope(productID uuid.UUID, name, description string) (*models.Scope, error) {
	if s.CreateScopeErr != nil {
		return nil, s.CreateScopeErr
	}
	return s.Store.CreateScope(productID, name, description)
}

func (s StoreWrapper) GetScope(id uuid.UUID) (*models.Scope, error) {
	if s.GetScopeErr != nil {
		return nil, s.GetScopeErr
	}
	if s.GetScopeMissing {
		return nil, store.ErrNotFound
	}
	return s.Store.GetScope(id)
}

func (s StoreWrapper) GetScopeInProject(projectID, scopeID uuid.UUID) (*models.Scope, error) {
	return s.GetScope(scopeID)
}

func (s StoreWrapper) DeleteScope(id uuid.UUID) error {
	if s.DeleteScopeErr != nil {
		return s.DeleteScopeErr
	}
	return s.Store.DeleteScope(id)
}

func (s StoreWrapper) EnsureProduct(name, description string) (*models.Product, bool, error) {
	if s.EnsureProductErr != nil {
		return nil, false, s.EnsureProductErr
	}
	return s.Store.EnsureProduct(name, description)
}

func (s StoreWrapper) EnsureProductInProject(projectID uuid.UUID, name, description string) (*models.Product, bool, error) {
	return s.EnsureProduct(name, description)
}

func (s StoreWrapper) EnsureScope(productID uuid.UUID, name, description string) (*models.Scope, bool, error) {
	if s.EnsureScopeErr != nil {
		return nil, false, s.EnsureScopeErr
	}
	return s.Store.EnsureScope(productID, name, description)
}

func (s StoreWrapper) EnsureTest(scopeID uuid.UUID, name, sbomStandard, sbomSpecVersion string) (*models.Test, bool, error) {
	if s.EnsureTestErr != nil {
		return nil, false, s.EnsureTestErr
	}
	return s.Store.EnsureTest(scopeID, name, sbomStandard, sbomSpecVersion)
}

func (s StoreWrapper) GetTest(id uuid.UUID) (*models.Test, error) {
	if s.GetTestErr != nil {
		return nil, s.GetTestErr
	}
	if s.GetTestMissing {
		return nil, store.ErrNotFound
	}
	return s.Store.GetTest(id)
}

func (s StoreWrapper) GetTestInProject(projectID, testID uuid.UUID) (*models.Test, error) {
	return s.GetTest(testID)
}

func (s StoreWrapper) ListTests(scopeID uuid.UUID) ([]models.Test, error) {
	if s.ListTestsErr != nil {
		return nil, s.ListTestsErr
	}
	return s.Store.ListTests(scopeID)
}

func (s StoreWrapper) ListRevisions(testID uuid.UUID) ([]models.TestRevision, error) {
	if s.ListRevisionsErr != nil {
		return nil, s.ListRevisionsErr
	}
	return s.Store.ListRevisions(testID)
}

func (s StoreWrapper) DeleteTest(id uuid.UUID) error {
	if s.DeleteTestErr != nil {
		return s.DeleteTestErr
	}
	return s.Store.DeleteTest(id)
}

func (s StoreWrapper) GetRevision(id uuid.UUID) (*models.TestRevision, error) {
	if s.GetRevisionErr != nil {
		return nil, s.GetRevisionErr
	}
	if s.GetRevisionMissing {
		return nil, store.ErrNotFound
	}
	return s.Store.GetRevision(id)
}

func (s StoreWrapper) GetRevisionInProject(projectID, revisionID uuid.UUID) (*models.TestRevision, error) {
	return s.GetRevision(revisionID)
}

func (s StoreWrapper) GetSbomBySHA(sha string) (*store.SbomObject, error) {
	if s.GetSbomErr != nil {
		return nil, s.GetSbomErr
	}
	return s.Store.GetSbomBySHA(sha)
}

func (s StoreWrapper) ListAllRevisions() ([]models.TestRevision, error) {
	if s.ListAllRevisionsErr != nil {
		return nil, s.ListAllRevisionsErr
	}
	return s.Store.ListAllRevisions()
}

func (s StoreWrapper) ListComponents(testID uuid.UUID) ([]models.Component, error) {
	if s.ListComponentsErr != nil {
		return nil, s.ListComponentsErr
	}
	if s.ListComponentsItems != nil {
		return s.ListComponentsItems, nil
	}
	return s.Store.ListComponents(testID)
}

func (s StoreWrapper) ListComponentsPage(
	testID uuid.UUID,
	filter store.ComponentListFilter,
	sort store.ComponentListSort,
	limit, offset int,
) ([]models.Component, error) {
	if s.ListComponentsPageErr != nil {
		return nil, s.ListComponentsPageErr
	}
	if s.ListComponentsPageItems != nil {
		return s.ListComponentsPageItems, nil
	}
	return s.Store.ListComponentsPage(testID, filter, sort, limit, offset)
}

func (s StoreWrapper) CountComponents(testID uuid.UUID) (int, error) {
	if s.CountComponentsErr != nil {
		return 0, s.CountComponentsErr
	}
	if s.CountComponentsValue != nil {
		return *s.CountComponentsValue, nil
	}
	return s.Store.CountComponents(testID)
}

func (s StoreWrapper) GetComponent(testID, componentID uuid.UUID) (*models.Component, error) {
	if s.GetComponentErr != nil {
		return nil, s.GetComponentErr
	}
	if s.GetComponentMissing {
		return nil, store.ErrNotFound
	}
	if s.GetComponentItem != nil {
		return s.GetComponentItem, nil
	}
	return s.Store.GetComponent(testID, componentID)
}

func (s StoreWrapper) SearchComponentOccurrencesPage(query string, limit, offset int) ([]store.ComponentOccurrence, int, error) {
	if s.SearchComponentOccurrencesErr != nil {
		return nil, 0, s.SearchComponentOccurrencesErr
	}
	if s.SearchComponentOccurrencesItems != nil {
		return s.SearchComponentOccurrencesItems, s.SearchComponentOccurrencesTotal, nil
	}
	return s.Store.SearchComponentOccurrencesPage(query, limit, offset)
}

func (s StoreWrapper) SearchComponentOccurrencesPageByProject(projectID uuid.UUID, query string, limit, offset int) ([]store.ComponentOccurrence, int, error) {
	return s.SearchComponentOccurrencesPage(query, limit, offset)
}

func (s StoreWrapper) DeleteRevision(id uuid.UUID) error {
	if s.DeleteRevisionErr != nil {
		return s.DeleteRevisionErr
	}
	return s.Store.DeleteRevision(id)
}

func (s StoreWrapper) DeleteRevisionInProject(projectID, revisionID uuid.UUID) error {
	return s.DeleteRevision(revisionID)
}

func (s StoreWrapper) ListAllScopes() ([]models.Scope, error) {
	if s.ListAllScopesErr != nil {
		return nil, s.ListAllScopesErr
	}
	return s.Store.ListAllScopes()
}

func (s StoreWrapper) ListAllScopesByProject(projectID uuid.UUID) ([]models.Scope, error) {
	return s.ListAllScopes()
}

func (s StoreWrapper) ListAllTests() ([]models.Test, error) {
	if s.ListAllTestsErr != nil {
		return nil, s.ListAllTestsErr
	}
	return s.Store.ListAllTests()
}

func (s StoreWrapper) ListAllTestsByProject(projectID uuid.UUID) ([]models.Test, error) {
	return s.ListAllTests()
}

func (s StoreWrapper) ListProjectsForUser(userID uuid.UUID, includeAll bool) ([]models.Project, error) {
	if s.ListProjectsForUserErr != nil {
		return nil, s.ListProjectsForUserErr
	}
	if s.ListProjectsForUserItems != nil {
		return s.ListProjectsForUserItems, nil
	}
	if s.Store == nil {
		return []models.Project{}, nil
	}
	return s.Store.ListProjectsForUser(userID, includeAll)
}

func (s StoreWrapper) GetProject(id uuid.UUID) (*models.Project, error) {
	if s.GetProjectErrOverride != nil {
		return nil, s.GetProjectErrOverride
	}
	if s.GetProjectItem != nil {
		return s.GetProjectItem, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.GetProject(id)
}

func (s StoreWrapper) UpdateProject(id uuid.UUID, name, description string) (*models.Project, error) {
	if s.UpdateProjectErr != nil {
		return nil, s.UpdateProjectErr
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.UpdateProject(id, name, description)
}

func (s StoreWrapper) EnsureUserSettings(userID uuid.UUID) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.EnsureUserSettings(userID)
}

func (s StoreWrapper) GetSelectedProjectID(userID uuid.UUID) (*uuid.UUID, error) {
	if s.Store == nil {
		return nil, nil
	}
	return s.Store.GetSelectedProjectID(userID)
}

func (s StoreWrapper) SetSelectedProjectID(userID, projectID uuid.UUID) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.SetSelectedProjectID(userID, projectID)
}

func (s StoreWrapper) UserHasProjectAccess(userID, projectID uuid.UUID, includeAll bool) (bool, error) {
	if s.Store == nil {
		return true, nil
	}
	return s.Store.UserHasProjectAccess(userID, projectID, includeAll)
}

func (s StoreWrapper) ListGlobalConnectorConfigs() ([]store.ConnectorConfig, error) {
	if s.ListGlobalConnectorConfigsErr != nil {
		return nil, s.ListGlobalConnectorConfigsErr
	}
	if s.GlobalConnectorConfigs != nil {
		return s.GlobalConnectorConfigs, nil
	}
	if s.Store == nil {
		return []store.ConnectorConfig{}, nil
	}
	return s.Store.ListGlobalConnectorConfigs()
}

func (s StoreWrapper) GetGlobalConnectorConfig(connectorType store.ConnectorType) (*store.ConnectorConfig, error) {
	if s.GetGlobalConnectorConfigErr != nil {
		return nil, s.GetGlobalConnectorConfigErr
	}
	if s.GlobalConnectorConfig != nil {
		return s.GlobalConnectorConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.GetGlobalConnectorConfig(connectorType)
}

func (s StoreWrapper) UpsertGlobalConnectorConfig(connectorType store.ConnectorType, configJSON json.RawMessage, isEnabled bool) (*store.ConnectorConfig, error) {
	if s.UpsertGlobalConnectorConfigErr != nil {
		return nil, s.UpsertGlobalConnectorConfigErr
	}
	if s.UpdatedConnectorConfig != nil {
		return s.UpdatedConnectorConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.UpsertGlobalConnectorConfig(connectorType, configJSON, isEnabled)
}

func (s StoreWrapper) UpdateGlobalConnectorTestStatus(connectorType store.ConnectorType, status store.ConnectorTestStatus, message string, testedAt time.Time) (*store.ConnectorConfig, error) {
	if s.UpdateConnectorTestStatusErr != nil {
		return nil, s.UpdateConnectorTestStatusErr
	}
	if s.ConnectorTestStatusConfig != nil {
		return s.ConnectorTestStatusConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.UpdateGlobalConnectorTestStatus(connectorType, status, message, testedAt)
}

func (s StoreWrapper) ListProjectConnectorConfigs(projectID uuid.UUID) ([]store.ConnectorConfig, error) {
	if s.ListProjectConnectorConfigsErr != nil {
		return nil, s.ListProjectConnectorConfigsErr
	}
	if s.ProjectConnectorConfigs != nil {
		return s.ProjectConnectorConfigs, nil
	}
	if s.Store == nil {
		return []store.ConnectorConfig{}, nil
	}
	return s.Store.ListProjectConnectorConfigs(projectID)
}

func (s StoreWrapper) GetProjectConnectorConfig(projectID uuid.UUID, connectorType store.ConnectorType) (*store.ConnectorConfig, error) {
	if s.GetProjectConnectorConfigErr != nil {
		return nil, s.GetProjectConnectorConfigErr
	}
	if s.ProjectConnectorConfig != nil {
		return s.ProjectConnectorConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.GetProjectConnectorConfig(projectID, connectorType)
}

func (s StoreWrapper) UpsertProjectConnectorConfig(projectID uuid.UUID, connectorType store.ConnectorType, configJSON json.RawMessage, isEnabled bool) (*store.ConnectorConfig, error) {
	if s.UpsertProjectConnectorConfigErr != nil {
		return nil, s.UpsertProjectConnectorConfigErr
	}
	if s.UpdatedProjectConnectorConfig != nil {
		return s.UpdatedProjectConnectorConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.UpsertProjectConnectorConfig(projectID, connectorType, configJSON, isEnabled)
}

func (s StoreWrapper) UpdateProjectConnectorTestStatus(projectID uuid.UUID, connectorType store.ConnectorType, status store.ConnectorTestStatus, message string, testedAt time.Time) (*store.ConnectorConfig, error) {
	if s.UpdateProjectConnectorTestErr != nil {
		return nil, s.UpdateProjectConnectorTestErr
	}
	if s.ProjectConnectorTestStatusConfig != nil {
		return s.ProjectConnectorTestStatusConfig, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.UpdateProjectConnectorTestStatus(projectID, connectorType, status, message, testedAt)
}

func (s StoreWrapper) CreateIngestJob(input store.IngestRequest) (*store.IngestJob, error) {
	if s.CreateIngestJobErr != nil {
		return nil, s.CreateIngestJobErr
	}
	return s.Store.CreateIngestJob(input)
}

func (s StoreWrapper) UpdateIngestJobStatus(id uuid.UUID, status string, errorMessage string) error {
	if s.UpdateIngestStatusErr != nil {
		return s.UpdateIngestStatusErr
	}
	return s.Store.UpdateIngestJobStatus(id, status, errorMessage)
}

func (s StoreWrapper) AddRevision(testID uuid.UUID, input store.RevisionInput) (*models.TestRevision, error) {
	if s.AddRevisionErr != nil {
		return nil, s.AddRevisionErr
	}
	return s.Store.AddRevision(testID, input)
}

func (s StoreWrapper) EnqueueTestRevisionFindingDiff(toRevisionID uuid.UUID, reason string) (*models.TestRevisionFindingDiffQueueItem, error) {
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.EnqueueTestRevisionFindingDiff(toRevisionID, reason)
}

func (s StoreWrapper) ClaimTestRevisionFindingDiffJobs(limit int, lockedBy string) ([]models.TestRevisionFindingDiffQueueItem, error) {
	if s.Store == nil {
		return nil, nil
	}
	return s.Store.ClaimTestRevisionFindingDiffJobs(limit, lockedBy)
}

func (s StoreWrapper) UpdateTestRevisionFindingDiffQueueStatus(id uuid.UUID, status, lastError string) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.UpdateTestRevisionFindingDiffQueueStatus(id, status, lastError)
}

func (s StoreWrapper) ComputeAndStoreTestRevisionFindingDiff(toRevisionID uuid.UUID) (*models.TestRevisionChangeSummary, error) {
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.ComputeAndStoreTestRevisionFindingDiff(toRevisionID)
}

func (s StoreWrapper) ListTestRevisionLastChanges(testID uuid.UUID) ([]models.TestRevisionChangeSummary, error) {
	if s.ListTestRevisionLastChangesErr != nil {
		return nil, s.ListTestRevisionLastChangesErr
	}
	if s.ListTestRevisionLastChangesItems != nil {
		return s.ListTestRevisionLastChangesItems, nil
	}
	if s.Store == nil {
		return []models.TestRevisionChangeSummary{}, nil
	}
	return s.Store.ListTestRevisionLastChanges(testID)
}

func (s StoreWrapper) GetTestRevisionChangeSummary(testID, revisionID uuid.UUID) (*models.TestRevisionChangeSummary, error) {
	if s.GetTestRevisionChangeSummaryErr != nil {
		return nil, s.GetTestRevisionChangeSummaryErr
	}
	if s.GetTestRevisionChangeSummaryItem != nil {
		return s.GetTestRevisionChangeSummaryItem, nil
	}
	if s.Store == nil {
		return nil, store.ErrNotFound
	}
	return s.Store.GetTestRevisionChangeSummary(testID, revisionID)
}

func (s StoreWrapper) ListTestRevisionFindingDiffs(testID, revisionID uuid.UUID, diffTypes []string) ([]models.TestRevisionFindingDiff, error) {
	if s.ListTestRevisionFindingDiffsErr != nil {
		return nil, s.ListTestRevisionFindingDiffsErr
	}
	if s.ListTestRevisionFindingDiffsItems != nil {
		return s.ListTestRevisionFindingDiffsItems, nil
	}
	if s.Store == nil {
		return []models.TestRevisionFindingDiff{}, nil
	}
	return s.Store.ListTestRevisionFindingDiffs(testID, revisionID, diffTypes)
}

func (s StoreWrapper) ListUsers() ([]models.User, error) {
	if s.ListUsersErr != nil {
		return nil, s.ListUsersErr
	}
	return s.Store.ListUsers()
}

func (s StoreWrapper) DeleteUser(id uuid.UUID) error {
	if s.DeleteUserErr != nil {
		return s.DeleteUserErr
	}
	return s.Store.DeleteUser(id)
}

func (s StoreWrapper) EnqueueComponentAnalysis(componentPURL, reason string, scheduledFor *time.Time) (*models.ComponentAnalysisQueueItem, error) {
	if s.EnqueueComponentAnalysisErr != nil {
		return nil, s.EnqueueComponentAnalysisErr
	}
	if s.EnqueueComponentAnalysisItem != nil {
		return s.EnqueueComponentAnalysisItem, nil
	}
	return s.Store.EnqueueComponentAnalysis(componentPURL, reason, scheduledFor)
}

func (s StoreWrapper) ListComponentAnalysisQueue(filter store.ComponentAnalysisQueueFilter) ([]models.ComponentAnalysisQueueItem, error) {
	if s.ListComponentAnalysisQueueErr != nil {
		return nil, s.ListComponentAnalysisQueueErr
	}
	if s.ComponentAnalysisQueueItems != nil {
		return s.ComponentAnalysisQueueItems, nil
	}
	return s.Store.ListComponentAnalysisQueue(filter)
}

func (s StoreWrapper) GetComponentAnalysisQueueItem(id uuid.UUID) (*models.ComponentAnalysisQueueItem, error) {
	if s.GetComponentAnalysisQueueErr != nil {
		return nil, s.GetComponentAnalysisQueueErr
	}
	if s.ComponentAnalysisQueueItem != nil {
		return s.ComponentAnalysisQueueItem, nil
	}
	return s.Store.GetComponentAnalysisQueueItem(id)
}

func (s StoreWrapper) ListComponentAnalysisFindings(componentPURL string) ([]models.ComponentAnalysisFinding, error) {
	if s.ListComponentAnalysisFindingsErr != nil {
		return nil, s.ListComponentAnalysisFindingsErr
	}
	if s.ComponentAnalysisFindings != nil {
		return s.ComponentAnalysisFindings, nil
	}
	return s.Store.ListComponentAnalysisFindings(componentPURL)
}

func (s StoreWrapper) GetComponentAnalysisFinding(id uuid.UUID) (*models.ComponentAnalysisFinding, error) {
	if s.GetComponentAnalysisFindingErr != nil {
		return nil, s.GetComponentAnalysisFindingErr
	}
	if s.ComponentAnalysisFinding != nil {
		return s.ComponentAnalysisFinding, nil
	}
	return s.Store.GetComponentAnalysisFinding(id)
}

func (s StoreWrapper) EnqueueAlertDispatchJob(input store.AlertDispatchEnqueueInput) (*store.AlertDispatchJob, error) {
	if s.EnqueueAlertDispatchErr != nil {
		return nil, s.EnqueueAlertDispatchErr
	}
	if s.EnqueueAlertDispatchItem != nil {
		return s.EnqueueAlertDispatchItem, nil
	}
	if s.Store == nil {
		return nil, nil
	}
	return s.Store.EnqueueAlertDispatchJob(input)
}
