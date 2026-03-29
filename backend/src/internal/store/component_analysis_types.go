package store

import "time"

// ComponentAnalysisQueueFilter defines filters for listing component analysis queue items.
type ComponentAnalysisQueueFilter struct {
	ComponentPURL string
	Status        string
	From          *time.Time
	To            *time.Time
	Limit         int
	Offset        int
}
