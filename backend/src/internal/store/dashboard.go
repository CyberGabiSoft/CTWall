package store

import (
	"time"

	"github.com/google/uuid"
)

const (
	DefaultDashboardTopN = 5
)

// DashboardOverviewQuery defines filters for dashboard overview aggregates.
type DashboardOverviewQuery struct {
	ProjectIDs []uuid.UUID
	Since      time.Time
	TopN       int
}

// DashboardOverview represents platform-wide dashboard aggregates.
type DashboardOverview struct {
	GeneratedAt  time.Time `json:"generatedAt"`
	RangeStart   time.Time `json:"rangeStart"`
	RangeEnd     time.Time `json:"rangeEnd"`
	ProjectCount int       `json:"projectCount"`
	TopN         int       `json:"topN"`

	KPIs                DashboardKPIs                `json:"kpis"`
	VerdictDistribution DashboardVerdictDistribution `json:"verdictDistribution"`

	TopProductsTotal     int                       `json:"topProductsTotal"`
	TopScopesTotal       int                       `json:"topScopesTotal"`
	TopPackageTypesTotal int                       `json:"topPackageTypesTotal"`
	TopLicensesTotal     int                       `json:"topLicensesTotal"`
	TopProducts          []DashboardTopItem        `json:"topProducts"`
	TopScopes            []DashboardTopItem        `json:"topScopes"`
	TopPackageTypes      []DashboardPackageType    `json:"topPackageTypes"`
	TopLicenses          []DashboardLicense        `json:"topLicenses"`
	TopMalwarePackages   []DashboardMalwarePackage `json:"topMalwarePackages"`
	RecentIngest         []DashboardIngestActivity `json:"recentIngest"`
	IngestTrend          []DashboardIngestBucket   `json:"ingestTrend"`
}

// DashboardKPIs stores high-signal dashboard metric cards.
type DashboardKPIs struct {
	MalwareActive                int        `json:"malwareActive"`
	AffectedTests                int        `json:"affectedTests"`
	OldestPackageScanAt          *time.Time `json:"oldestPackageScanAt,omitempty"`
	LastAnalysisAt               *time.Time `json:"lastAnalysisAt,omitempty"`
	LastMalwareSummaryComputedAt *time.Time `json:"lastMalwareSummaryComputedAt,omitempty"`
	IngestImports                int        `json:"ingestImports"`
	IngestComponents             int        `json:"ingestComponents"`
	OverridesActive              int        `json:"overridesActive"`
}

// DashboardVerdictDistribution is the active-snapshot verdict split by unique PURL.
type DashboardVerdictDistribution struct {
	Malware int `json:"malware"`
	Clean   int `json:"clean"`
	Unknown int `json:"unknown"`
}

// DashboardTopItem is a generic name/value ranking item.
type DashboardTopItem struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// DashboardPackageType represents active inventory distribution by package type.
type DashboardPackageType struct {
	PackageType string  `json:"packageType"`
	Count       int     `json:"count"`
	Percentage  float64 `json:"percentage"`
}

// DashboardLicense represents active inventory distribution by license.
type DashboardLicense struct {
	License    string  `json:"license"`
	Count      int     `json:"count"`
	Percentage float64 `json:"percentage"`
}

// DashboardMalwarePackage represents top malware package occurrence in active revisions.
type DashboardMalwarePackage struct {
	PURL        string     `json:"purl"`
	Occurrences int        `json:"occurrences"`
	LastSeenAt  *time.Time `json:"lastSeenAt,omitempty"`
}

// DashboardIngestActivity represents recent ingest pipeline activity.
type DashboardIngestActivity struct {
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

// DashboardIngestBucket represents completed ingest volume in time buckets.
type DashboardIngestBucket struct {
	BucketStart        time.Time `json:"bucketStart"`
	Imports            int       `json:"imports"`
	ComponentsImported int       `json:"componentsImported"`
}
