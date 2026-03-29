package store

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound indicates a missing entity in the store.
	ErrNotFound = errors.New("not found")
	// ErrAlreadyExists indicates a conflict when creating a new entity.
	ErrAlreadyExists = errors.New("already exists")
	// ErrBusy indicates the requested operation is already in progress.
	ErrBusy = errors.New("busy")
	// ErrInvalidPayload indicates invalid input data for store operations.
	ErrInvalidPayload = errors.New("invalid payload")
	// ErrInvalidStateTransition indicates an invalid state change.
	ErrInvalidStateTransition = errors.New("invalid state transition")
	// ErrForbidden indicates the operation is not allowed for the caller.
	ErrForbidden = errors.New("forbidden")
)

// SbomObject stores the raw SBOM content and metadata keyed by SHA256.
type SbomObject struct {
	SHA         string
	Bytes       []byte
	StoragePath string
	Format      string
	ContentType string
	IsGzip      bool
	CreatedAt   time.Time
}

// RevisionInput represents the fields required to create a new test revision.
type RevisionInput struct {
	SbomSha256              string
	SbomProducer            string
	Tags                    []string
	MetadataJSON            json.RawMessage
	SbomMetadataJSON        json.RawMessage
	ComponentsImportedCount int
	Components              []ComponentInput
}

// ComponentInput represents a normalized SBOM component to persist.
type ComponentInput struct {
	PURL         string
	PkgName      string
	Version      string
	PkgType      string
	PkgNamespace string
	SbomType     string
	Publisher    string
	Supplier     string
	Licenses     json.RawMessage
	Properties   json.RawMessage
}

// ProjectMemberAssignment describes a desired project membership row.
type ProjectMemberAssignment struct {
	UserID      uuid.UUID
	ProjectRole string
}

// GroupMemberAssignment describes a desired group membership row.
type GroupMemberAssignment struct {
	UserID uuid.UUID
	Role   string
}

// ProductGroupGrantAssignment describes a desired explicit product group grant.
type ProductGroupGrantAssignment struct {
	GroupID uuid.UUID
	Role    string
}
