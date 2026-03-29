package store

import (
	"time"

	"github.com/google/uuid"
)

const (
	DefaultPostureTopN   = 5
	DefaultPostureBucket = "day"
)

// SecurityPostureOverviewQuery defines filters for security posture aggregates.
type SecurityPostureOverviewQuery struct {
	ProjectID uuid.UUID
	Since     time.Time
	TopN      int
	Bucket    string
}

// SecurityPostureOverview is a project-scoped technical posture snapshot.
type SecurityPostureOverview struct {
	GeneratedAt time.Time `json:"generatedAt"`
	RangeStart  time.Time `json:"rangeStart"`
	RangeEnd    time.Time `json:"rangeEnd"`
	ProjectID   uuid.UUID `json:"projectId"`
	TopN        int       `json:"topN"`
	Bucket      string    `json:"bucket"`

	Score SecurityPostureScore `json:"score"`
	KPIs  SecurityPostureKPIs  `json:"kpis"`

	IngestTrend            []SecurityPostureIngestBucket `json:"ingestTrend"`
	IngestFailureTop       []SecurityPostureTopItem      `json:"ingestFailureTop"`
	OsvSyncTrend           []SecurityPostureSyncBucket   `json:"osvSyncTrend"`
	OsvTopErrorStages      []SecurityPostureTopItem      `json:"osvTopErrorStages"`
	InventoryTopTypesTotal int                           `json:"inventoryTopTypesTotal"`
	InventoryTopTypes      []SecurityPosturePackageType  `json:"inventoryTopTypes"`
	RecentUploads          []SecurityPostureUpload       `json:"recentUploads"`
	RecentFailures         []SecurityPostureFailure      `json:"recentFailures"`
}

// SecurityPostureScore is a synthesized 0-100 score.
type SecurityPostureScore struct {
	Value int    `json:"value"`
	Label string `json:"label"`
}

// SecurityPostureKPIs stores top technical posture indicators.
type SecurityPostureKPIs struct {
	TotalProducts        int        `json:"totalProducts"`
	MalwareProducts      int        `json:"malwareProducts"`
	UnknownPending       int        `json:"unknownPending"`
	ActiveComponents     int        `json:"activeComponents"`
	IngestFailures       int        `json:"ingestFailures"`
	IngestCompleted      int        `json:"ingestCompleted"`
	IngestFailurePercent float64    `json:"ingestFailurePercent"`
	OsvSyncStatus        string     `json:"osvSyncStatus"`
	OsvLastSyncAt        *time.Time `json:"osvLastSyncAt,omitempty"`
	OsvErrors            int        `json:"osvErrors"`
	OpenErrorEvents      int        `json:"openErrorEvents"`
	QueueBacklog         int        `json:"queueBacklog"`
	InventoryTopType     string     `json:"inventoryTopType"`
	LastAnalysisAt       *time.Time `json:"lastAnalysisAt,omitempty"`
}

// SecurityPostureTopItem is a generic name/value ranking item.
type SecurityPostureTopItem struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// SecurityPostureIngestBucket represents project ingest volume and failures per bucket.
type SecurityPostureIngestBucket struct {
	BucketStart time.Time `json:"bucketStart"`
	Imports     int       `json:"imports"`
	Failures    int       `json:"failures"`
}

// SecurityPostureSyncBucket represents global OSV sync run activity per bucket.
type SecurityPostureSyncBucket struct {
	BucketStart time.Time `json:"bucketStart"`
	Runs        int       `json:"runs"`
	Failures    int       `json:"failures"`
}

// SecurityPosturePackageType represents active inventory distribution by package type.
type SecurityPosturePackageType struct {
	PackageType string  `json:"packageType"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
}

// SecurityPostureUpload represents recent upload activity in ingest queue.
type SecurityPostureUpload struct {
	ID                 uuid.UUID `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	Status             string    `json:"status"`
	Stage              string    `json:"stage"`
	ComponentsImported int       `json:"componentsImported"`
	ProductID          string    `json:"productId,omitempty"`
	ScopeID            string    `json:"scopeId,omitempty"`
	TestID             string    `json:"testId,omitempty"`
	ProductName        string    `json:"productName"`
	ScopeName          string    `json:"scopeName"`
	TestName           string    `json:"testName"`
	ErrorMessage       string    `json:"errorMessage,omitempty"`
}

// SecurityPostureFailure represents recent technical failures for triage.
type SecurityPostureFailure struct {
	Timestamp time.Time `json:"timestamp"`
	Component string    `json:"component"`
	Summary   string    `json:"summary"`
	Status    string    `json:"status"`
}
