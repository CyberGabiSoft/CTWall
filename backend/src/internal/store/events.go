package store

import (
	"strings"
	"time"

	"backend/internal/eventmeta"
)

type EventsStatus string

const (
	EventsStatusOpen         EventsStatus = "open"
	EventsStatusAcknowledged EventsStatus = "acknowledged"
)

type EventsViewerRole string

const (
	EventsViewerRoleAdmin EventsViewerRole = "admin"
	EventsViewerRoleWrite EventsViewerRole = "write"
	EventsViewerRoleRead  EventsViewerRole = "read"
)

type EventsQuery struct {
	// Filters (backend-enforced).
	Severities []eventmeta.Severity
	// Categories are aligned to severity. Empty slice means "all categories" for that severity.
	CategoriesError []eventmeta.Category
	CategoriesWarn  []eventmeta.Category
	CategoriesInfo  []eventmeta.Category
	Status          EventsStatus

	From time.Time
	To   time.Time

	// Optional query string to match in title/message/event_key.
	Query string
	// Active project filter for workspace-scoped events.
	// Global events without projectId are still included.
	ProjectID string

	// Pagination.
	Limit  int
	Offset int

	// RBAC enforcement.
	ViewerRole EventsViewerRole
	ViewerID   string // UUID string (self-only filter for reader); empty for non-reader.
}

type EventAggregate struct {
	EventKey       string     `json:"eventKey"`
	Category       string     `json:"category"`
	Severity       string     `json:"severity"`
	MinRole        string     `json:"minRole"`
	Title          string     `json:"title"`
	Message        string     `json:"message"`
	Component      string     `json:"component"`
	ErrorID        string     `json:"errorId,omitempty"`
	ProjectID      string     `json:"projectId,omitempty"`
	FirstSeenAt    time.Time  `json:"firstSeenAt"`
	LastSeenAt     time.Time  `json:"lastSeenAt"`
	Occurrences    int        `json:"occurrences"`
	AcknowledgedAt *time.Time `json:"acknowledgedAt,omitempty"`
	Status         string     `json:"status"`
}

func (q *EventsQuery) NormalizeDefaults() {
	if q == nil {
		return
	}
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	if q.From.IsZero() {
		// Open events are a "hot" view; acknowledged events are a "closed cases" view
		// that should keep visibility for longer by default.
		window := 90 * 24 * time.Hour
		if q.Status == EventsStatusAcknowledged {
			window = 365 * 24 * time.Hour
		}
		q.From = time.Now().UTC().Add(-window)
	}
	if q.To.IsZero() {
		q.To = time.Now().UTC()
	}
	if q.Status == "" {
		q.Status = EventsStatusOpen
	}
	q.Query = strings.TrimSpace(q.Query)
}
