package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Product represents the top-level business entity (e.g., "Online Banking").
type Product struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	ProjectID    uuid.UUID  `json:"projectId" db:"project_id"`
	Name         string     `json:"name" db:"name"`
	Description  string     `json:"description,omitempty" db:"description"`
	OwnerGroupID *uuid.UUID `json:"ownerGroupId,omitempty" db:"owner_group_id"`
	CreatedBy    *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
	ArchivedAt   *time.Time `json:"archivedAt,omitempty" db:"archived_at"`
	CreatedAt    time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt    time.Time  `json:"updatedAt" db:"updated_at"`
}

// Project represents a top-level workspace used to scope all product data.
type Project struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	ArchivedAt  *time.Time `json:"archivedAt,omitempty" db:"archived_at"`
	CreatedBy   *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt" db:"updated_at"`
}

// ProjectMembership links users to projects they can access.
type ProjectMembership struct {
	ProjectID   uuid.UUID  `json:"projectId" db:"project_id"`
	UserID      uuid.UUID  `json:"userId" db:"user_id"`
	ProjectRole string     `json:"projectRole" db:"project_role"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	CreatedBy   *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
}

// ProjectMember is a denormalized view of user + project membership role.
type ProjectMember struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	Nickname    string    `json:"nickname" db:"nickname"`
	Role        string    `json:"role" db:"role"`
	AccountType string    `json:"accountType" db:"account_type"`
	FullName    string    `json:"fullName,omitempty" db:"full_name"`
	ProjectRole string    `json:"projectRole" db:"project_role"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
}

// UserGroup represents a project-scoped authorization group.
type UserGroup struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ProjectID   uuid.UUID  `json:"projectId" db:"project_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	CreatedBy   *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
}

// UserGroupMember represents a user membership inside a group.
type UserGroupMember struct {
	GroupID   uuid.UUID  `json:"groupId" db:"group_id"`
	UserID    uuid.UUID  `json:"userId" db:"user_id"`
	Role      string     `json:"role" db:"role"`
	CreatedAt time.Time  `json:"createdAt" db:"created_at"`
	CreatedBy *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
	Email     string     `json:"email,omitempty" db:"email"`
	Nickname  string     `json:"nickname,omitempty" db:"nickname"`
	FullName  string     `json:"fullName,omitempty" db:"full_name"`
}

// ProductGroupGrant represents a non-owner group grant on a product.
type ProductGroupGrant struct {
	ProductID uuid.UUID  `json:"productId" db:"product_id"`
	GroupID   uuid.UUID  `json:"groupId" db:"group_id"`
	Role      string     `json:"role" db:"role"`
	CreatedAt time.Time  `json:"createdAt" db:"created_at"`
	CreatedBy *uuid.UUID `json:"createdBy,omitempty" db:"created_by"`
}

// UserSettings stores per-user UI/server preferences.
type UserSettings struct {
	UserID            uuid.UUID  `json:"userId" db:"user_id"`
	SelectedProjectID *uuid.UUID `json:"selectedProjectId,omitempty" db:"selected_project_id"`
	UpdatedAt         time.Time  `json:"updatedAt" db:"updated_at"`
}

// Scope represents a functional area within a product (e.g., "Payment Gateway").
type Scope struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ProductID   uuid.UUID  `json:"productId" db:"product_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	ArchivedAt  *time.Time `json:"archivedAt,omitempty" db:"archived_at"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt" db:"updated_at"`
}

// Test represents a logical container for SBOM revisions (e.g. a microservice).
type Test struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	ScopeID         uuid.UUID  `json:"scopeId" db:"scope_id"`
	Name            string     `json:"name" db:"name"`
	SbomStandard    string     `json:"sbomStandard" db:"sbom_standard"`
	SbomSpecVersion string     `json:"sbomSpecVersion" db:"sbom_spec_version"`
	IsPublic        bool       `json:"isPublic" db:"is_public"`
	PublicToken     string     `json:"publicToken,omitempty" db:"public_token"`
	ArchivedAt      *time.Time `json:"archivedAt,omitempty" db:"archived_at"`
	CreatedAt       time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt       time.Time  `json:"updatedAt" db:"updated_at"`
}

// TestRevision represents a single SBOM upload history entry.
type TestRevision struct {
	ID                      uuid.UUID       `json:"id" db:"id"`
	TestID                  uuid.UUID       `json:"testId" db:"test_id"`
	SbomSha256              string          `json:"sbomSha256" db:"sbom_sha256"`
	SbomProducer            string          `json:"sbomProducer" db:"sbom_producer"`
	Tags                    []string        `json:"tags" db:"tags"` // Stored as JSONB or Array
	MetadataJSON            json.RawMessage `json:"metadataJson" db:"metadata_json"`
	SbomMetadataJSON        json.RawMessage `json:"sbomMetadataJson,omitempty" db:"sbom_metadata_json"`
	ComponentsImportedCount int             `json:"componentsImportedCount" db:"components_imported_count"`
	IsActive                bool            `json:"isActive" db:"is_active"`
	LastModifiedAt          time.Time       `json:"lastModifiedAt" db:"last_modified_at"`
	CreatedAt               time.Time       `json:"createdAt" db:"created_at"`
}

// Component represents a software dependency found in an SBOM.
type Component struct {
	ID                      uuid.UUID       `json:"id" db:"id"`
	RevisionID              uuid.UUID       `json:"revisionId" db:"revision_id"`
	PURL                    string          `json:"purl" db:"purl"`
	PkgName                 string          `json:"pkgName" db:"pkg_name"`
	Version                 string          `json:"version" db:"version"`
	PkgType                 string          `json:"pkgType" db:"pkg_type"`
	PkgNamespace            string          `json:"pkgNamespace,omitempty" db:"pkg_namespace"`
	SbomType                string          `json:"sbomType,omitempty" db:"sbom_type"`
	Publisher               string          `json:"publisher,omitempty" db:"publisher"`
	Supplier                string          `json:"supplier,omitempty" db:"supplier"`
	Licenses                json.RawMessage `json:"licenses,omitempty" db:"licenses"`
	Properties              json.RawMessage `json:"properties,omitempty" db:"properties"`
	MalwareVerdict          string          `json:"malwareVerdict,omitempty" db:"malware_verdict"`
	MalwareFindingsCount    int             `json:"malwareFindingsCount,omitempty" db:"malware_findings_count"`
	MalwareTriageStatus     string          `json:"malwareTriageStatus,omitempty" db:"malware_triage_status"`
	MalwareScannedAt        *time.Time      `json:"malwareScannedAt,omitempty" db:"malware_scanned_at"`
	MalwareValidUntil       *time.Time      `json:"malwareValidUntil,omitempty" db:"malware_valid_until"`
	MalwarePURLs            []string        `json:"malwarePurls,omitempty" db:"malware_purls"`
	MalwareQueueStatus      string          `json:"malwareQueueStatus,omitempty" db:"malware_queue_status"`
	MalwareQueueCompletedAt *time.Time      `json:"malwareQueueCompletedAt,omitempty" db:"malware_queue_completed_at"`
	CreatedAt               time.Time       `json:"createdAt" db:"created_at"`
}

// User represents an authenticated system user.
type User struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Email       string    `json:"email" db:"email"`
	Nickname    string    `json:"nickname" db:"nickname"`
	Role        string    `json:"role" db:"role"`
	AccountType string    `json:"accountType" db:"account_type"`
	FullName    string    `json:"fullName,omitempty" db:"full_name"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
}

// ScanMalwareSource represents a configured external data source for malware scans.
type ScanMalwareSource struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	Name       string          `json:"name" db:"name"`
	SourceType string          `json:"sourceType" db:"source_type"`
	BaseURL    string          `json:"baseUrl" db:"base_url"`
	ConfigJSON json.RawMessage `json:"configJson" db:"config_json"`
	IsActive   bool            `json:"isActive" db:"is_active"`
	CreatedAt  time.Time       `json:"createdAt" db:"created_at"`
}

// Scanner represents a configured scanner tied to a malware source.
type Scanner struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	SourceID    uuid.UUID       `json:"sourceId" db:"source_id"`
	Name        string          `json:"name" db:"name"`
	ScannerType string          `json:"scannerType" db:"scanner_type"`
	Version     string          `json:"version,omitempty" db:"version"`
	ResultsPath string          `json:"resultsPath,omitempty" db:"results_path"`
	ConfigJSON  json.RawMessage `json:"configJson" db:"config_json"`
	CreatedAt   time.Time       `json:"createdAt" db:"created_at"`
}

// AnalysisQueueItem represents a queued malware analysis request.
type AnalysisQueueItem struct {
	ID            uuid.UUID `json:"id" db:"id"`
	ComponentPURL string    `json:"componentPurl" db:"component_purl"`
	ScannerID     uuid.UUID `json:"scannerId" db:"scanner_id"`
	Status        string    `json:"status" db:"status"`
	CreatedAt     time.Time `json:"createdAt" db:"created_at"`
}

// AnalysisResult is a summary of malware analysis for a component PURL.
type AnalysisResult struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ComponentPURL string     `json:"componentPurl" db:"component_purl"`
	ComponentHash string     `json:"componentHash,omitempty" db:"component_hash"`
	Verdict       string     `json:"verdict" db:"verdict"`
	FindingsCount int        `json:"findingsCount" db:"findings_count"`
	Summary       string     `json:"summary,omitempty" db:"summary"`
	ScannedAt     time.Time  `json:"scannedAt" db:"scanned_at"`
	ValidUntil    *time.Time `json:"validUntil,omitempty" db:"valid_until"`
}

// ComponentAnalysisQueueItem represents a queued component malware mapping run.
type ComponentAnalysisQueueItem struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	ComponentPURL string     `json:"componentPurl" db:"component_purl"`
	Status        string     `json:"status" db:"status"`
	Reason        string     `json:"reason" db:"reason"`
	Attempts      int        `json:"attempts" db:"attempts"`
	LastError     string     `json:"lastError,omitempty" db:"last_error"`
	LockedAt      *time.Time `json:"lockedAt,omitempty" db:"locked_at"`
	LockedBy      string     `json:"lockedBy,omitempty" db:"locked_by"`
	ScheduledFor  *time.Time `json:"scheduledFor,omitempty" db:"scheduled_for"`
	CreatedAt     time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt     time.Time  `json:"updatedAt" db:"updated_at"`
	CompletedAt   *time.Time `json:"completedAt,omitempty" db:"completed_at"`
}

// ComponentAnalysisFinding represents a mapping between component and malware PURLs.
type ComponentAnalysisFinding struct {
	ID                         uuid.UUID `json:"id" db:"id"`
	ComponentPURL              string    `json:"componentPurl" db:"component_purl"`
	MalwarePURL                string    `json:"malwarePurl" db:"malware_purl"`
	SourceMalwareInputResultID uuid.UUID `json:"sourceMalwareInputResultId" db:"source_malware_input_result_id"`
	MatchType                  string    `json:"matchType" db:"match_type"`
	CreatedAt                  time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt                  time.Time `json:"updatedAt" db:"updated_at"`

	// Triage is contextual (per test) and stored separately from the technical mapping table.
	// For API consumers that don't supply test context, these fields default to OPEN/P2.
	TriageStatus      string  `json:"triageStatus" db:"triage_status"`
	TriagePriority    *string `json:"triagePriority,omitempty" db:"triage_priority"`
	EffectivePriority string  `json:"effectivePriority" db:"effective_priority"`
}

// ComponentAnalysisMalwareSchedule represents the schedule for automatic re-analysis runs.
type ComponentAnalysisMalwareSchedule struct {
	Enabled         bool      `json:"enabled" db:"enabled"`
	IntervalSeconds int       `json:"intervalSeconds" db:"interval_seconds"`
	UpdatedAt       time.Time `json:"updatedAt" db:"updated_at"`
}

// ComponentAnalysisMalwareComponentState tracks the latest analysis run for a component PURL.
type ComponentAnalysisMalwareComponentState struct {
	ComponentPURL string     `json:"componentPurl" db:"component_purl"`
	ScannedAt     time.Time  `json:"scannedAt" db:"scanned_at"`
	ValidUntil    *time.Time `json:"validUntil,omitempty" db:"valid_until"`
	UpdatedAt     time.Time  `json:"updatedAt" db:"updated_at"`
}

// TestRevisionMalwareSummary is a materialized summary of malware components for a revision.
// Only the active TestRevision is used in the UI, but summaries are stored per revision.
type TestRevisionMalwareSummary struct {
	RevisionID            uuid.UUID  `json:"revisionId" db:"revision_id"`
	MalwareComponentCount int        `json:"malwareComponentCount" db:"malware_component_count"`
	ComputedAt            *time.Time `json:"computedAt,omitempty" db:"computed_at"`
	UpdatedAt             time.Time  `json:"updatedAt" db:"updated_at"`
}

// TestRevisionMalwareSummaryQueueItem represents a queued recomputation run for a revision summary.
type TestRevisionMalwareSummaryQueueItem struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	RevisionID  uuid.UUID  `json:"revisionId" db:"revision_id"`
	Status      string     `json:"status" db:"status"`
	Reason      string     `json:"reason" db:"reason"`
	Attempts    int        `json:"attempts" db:"attempts"`
	LastError   string     `json:"lastError,omitempty" db:"last_error"`
	LockedAt    *time.Time `json:"lockedAt,omitempty" db:"locked_at"`
	LockedBy    string     `json:"lockedBy,omitempty" db:"locked_by"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt" db:"updated_at"`
	CompletedAt *time.Time `json:"completedAt,omitempty" db:"completed_at"`
}

// TestRevisionChangeSummary stores system-computed delta counters for a revision reimport.
type TestRevisionChangeSummary struct {
	ToRevisionID    uuid.UUID  `json:"toRevisionId" db:"to_revision_id"`
	ProjectID       uuid.UUID  `json:"projectId" db:"project_id"`
	TestID          uuid.UUID  `json:"testId" db:"test_id"`
	FromRevisionID  *uuid.UUID `json:"fromRevisionId,omitempty" db:"from_revision_id"`
	AddedCount      int        `json:"addedCount" db:"added_count"`
	RemovedCount    int        `json:"removedCount" db:"removed_count"`
	UnchangedCount  int        `json:"unchangedCount" db:"unchanged_count"`
	ReappearedCount int        `json:"reappearedCount" db:"reappeared_count"`
	Status          string     `json:"status" db:"status"`
	ComputedAt      *time.Time `json:"computedAt,omitempty" db:"computed_at"`
	CreatedAt       time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt       time.Time  `json:"updatedAt" db:"updated_at"`
}

// TestRevisionFindingDiff represents one row-level malware delta entry for a reimport.
type TestRevisionFindingDiff struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ProjectID      uuid.UUID  `json:"projectId" db:"project_id"`
	TestID         uuid.UUID  `json:"testId" db:"test_id"`
	FromRevisionID *uuid.UUID `json:"fromRevisionId,omitempty" db:"from_revision_id"`
	ToRevisionID   uuid.UUID  `json:"toRevisionId" db:"to_revision_id"`
	FindingType    string     `json:"findingType" db:"finding_type"`
	DiffType       string     `json:"diffType" db:"diff_type"`
	ComponentPURL  string     `json:"componentPurl" db:"component_purl"`
	MalwarePURL    string     `json:"malwarePurl" db:"malware_purl"`
	CreatedAt      time.Time  `json:"createdAt" db:"created_at"`
}

// TestRevisionFindingDiffQueueItem represents an async diff computation job.
type TestRevisionFindingDiffQueueItem struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ProjectID      uuid.UUID  `json:"projectId" db:"project_id"`
	TestID         uuid.UUID  `json:"testId" db:"test_id"`
	FromRevisionID *uuid.UUID `json:"fromRevisionId,omitempty" db:"from_revision_id"`
	ToRevisionID   uuid.UUID  `json:"toRevisionId" db:"to_revision_id"`
	Status         string     `json:"status" db:"status"`
	Reason         string     `json:"reason" db:"reason"`
	Attempts       int        `json:"attempts" db:"attempts"`
	LastError      string     `json:"lastError,omitempty" db:"last_error"`
	LockedAt       *time.Time `json:"lockedAt,omitempty" db:"locked_at"`
	LockedBy       string     `json:"lockedBy,omitempty" db:"locked_by"`
	CreatedAt      time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt      time.Time  `json:"updatedAt" db:"updated_at"`
	CompletedAt    *time.Time `json:"completedAt,omitempty" db:"completed_at"`
}

// ScanComponentResult represents raw findings for a scanned component.
type ScanComponentResult struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	ComponentPURL    string          `json:"componentPurl" db:"component_purl"`
	ComponentHash    string          `json:"componentHash,omitempty" db:"component_hash"`
	AnalysisResultID *uuid.UUID      `json:"analysisResultId,omitempty" db:"analysis_result_id"`
	ScanID           uuid.UUID       `json:"scanId" db:"scan_id"`
	SourceID         uuid.UUID       `json:"sourceId" db:"source_id"`
	ResultFilename   string          `json:"resultFilename,omitempty" db:"result_filename"`
	Evidence         string          `json:"evidence,omitempty" db:"evidence"`
	DetailsJSON      json.RawMessage `json:"detailsJson" db:"details_json"`
	PublishedAt      *time.Time      `json:"publishedAt,omitempty" db:"published_at"`
	ModifiedAt       *time.Time      `json:"modifiedAt,omitempty" db:"modified_at"`
	DetectVersion    string          `json:"detectVersion,omitempty" db:"detect_version"`
	FixedVersion     string          `json:"fixedVersion,omitempty" db:"fixed_version"`
	IsMalware        bool            `json:"isMalware" db:"is_malware"`
	CreatedAt        time.Time       `json:"createdAt" db:"created_at"`
}

// AlertGroup represents a deduplicated (batched) alert state for a project.
// It is a read model used by the Alerts UI and by dispatch rate limiting.
type AlertGroup struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ProjectID      uuid.UUID  `json:"projectId" db:"project_id"`
	Severity       string     `json:"severity" db:"severity"` // INFO|WARN|ERROR
	Category       string     `json:"category" db:"category"` // eventmeta.Category values
	Type           string     `json:"type" db:"type"`         // low-cardinality (e.g. malware.detected)
	Status         string     `json:"status" db:"status"`     // OPEN|ACKNOWLEDGED|CLOSED
	GroupKey       string     `json:"groupKey" db:"group_key"`
	Title          string     `json:"title" db:"title"`
	EntityRef      *string    `json:"entityRef,omitempty" db:"entity_ref"`
	Occurrences    int        `json:"occurrences" db:"occurrences"`
	FirstSeenAt    time.Time  `json:"firstSeenAt" db:"first_seen_at"`
	LastSeenAt     time.Time  `json:"lastSeenAt" db:"last_seen_at"`
	LastNotifiedAt *time.Time `json:"lastNotifiedAt,omitempty" db:"last_notified_at"`

	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty" db:"acknowledged_at"`
	AcknowledgedBy *uuid.UUID `json:"acknowledgedBy,omitempty" db:"acknowledged_by"`
	ClosedAt       *time.Time `json:"closedAt,omitempty" db:"closed_at"`
	ClosedBy       *uuid.UUID `json:"closedBy,omitempty" db:"closed_by"`

	CreatedAt time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt time.Time `json:"updatedAt" db:"updated_at"`
}

// AlertDedupRule defines alert grouping (deduplication) for a given alert type in a project.
// The most specific rule wins during resolution (TEST > SCOPE > PRODUCT > GLOBAL).
type AlertDedupRule struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	ProjectID   uuid.UUID  `json:"projectId" db:"project_id"`
	AlertType   string     `json:"alertType" db:"alert_type"`
	DedupScope  string     `json:"dedupScope" db:"dedup_scope"` // GLOBAL|PRODUCT|SCOPE|TEST
	ProductID   *uuid.UUID `json:"productId,omitempty" db:"product_id"`
	ScopeID     *uuid.UUID `json:"scopeId,omitempty" db:"scope_id"`
	TestID      *uuid.UUID `json:"testId,omitempty" db:"test_id"`
	MinSeverity string     `json:"minSeverity" db:"min_severity"` // INFO|WARNING|ERROR
	Enabled     bool       `json:"enabled" db:"enabled"`
	CreatedAt   time.Time  `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time  `json:"updatedAt" db:"updated_at"`
}

// AlertOccurrence represents a single occurrence (append-only) associated with an AlertGroup.
type AlertOccurrence struct {
	ID        uuid.UUID `json:"id" db:"id"`
	ProjectID uuid.UUID `json:"projectId" db:"project_id"`
	GroupID   uuid.UUID `json:"groupId" db:"group_id"`
	// Group metadata (denormalized for the occurrences list UI).
	// These values come from alert_groups and are always present for list endpoints.
	Severity   string          `json:"severity,omitempty" db:"severity"` // INFO|WARN|ERROR
	Category   string          `json:"category,omitempty" db:"category"` // eventmeta.Category values
	Type       string          `json:"type,omitempty" db:"type"`         // low-cardinality (e.g. malware.detected)
	Title      string          `json:"title,omitempty" db:"title"`       // group title at the time of listing
	OccurredAt time.Time       `json:"occurredAt" db:"occurred_at"`
	ProductID  *uuid.UUID      `json:"productId,omitempty" db:"product_id"`
	ScopeID    *uuid.UUID      `json:"scopeId,omitempty" db:"scope_id"`
	TestID     *uuid.UUID      `json:"testId,omitempty" db:"test_id"`
	EntityRef  *string         `json:"entityRef,omitempty" db:"entity_ref"`
	Details    json.RawMessage `json:"details" db:"details"`
	CreatedAt  time.Time       `json:"createdAt" db:"created_at"`
}

// AuditLog represents an immutable audit log entry.
type AuditLog struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	ActorID    *uuid.UUID      `json:"actorId,omitempty" db:"actor_id"`
	Action     string          `json:"action" db:"action"`
	EntityType string          `json:"entityType" db:"entity_type"`
	EntityID   *uuid.UUID      `json:"entityId,omitempty" db:"entity_id"`
	Details    json.RawMessage `json:"details,omitempty" db:"details"`
	IPAddress  string          `json:"ipAddress,omitempty" db:"ip_address"`
	CreatedAt  time.Time       `json:"createdAt" db:"created_at"`
}
