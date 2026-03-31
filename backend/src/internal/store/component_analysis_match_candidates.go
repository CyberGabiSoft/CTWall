package store

import (
	"encoding/json"

	"github.com/google/uuid"
)

// MalwareMatchCandidate is a raw malware finding candidate used by component mapping.
// ComponentPURL comes from source_malware_input_component_results.component_purl.
// DetailsJSON comes from source_malware_input_component_results.details_json.
// SourceMalwareInputResultID links to the aggregated summary row used by findings table.
type MalwareMatchCandidate struct {
	ComponentPURL              string
	DetailsJSON                json.RawMessage
	SourceMalwareInputResultID uuid.UUID
}
