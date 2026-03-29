package store

import (
	"encoding/json"
	"time"

	"backend/internal/models"

	"github.com/google/uuid"
)

// UserCredentials contains a user and its password hash (for auth only).
type UserCredentials struct {
	User         models.User
	PasswordHash string
}

// APIToken represents a service token stored in the database.
type APIToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	TokenHash  string
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	CreatedAt  time.Time
}

// RefreshToken represents a browser refresh token stored in the database.
type RefreshToken struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	TokenHash    string
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	ReplacedByID *uuid.UUID
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	UserAgent    string
	IPAddress    string
}

// AuditLogEntry represents an immutable security audit log entry.
type AuditLogEntry struct {
	ActorID    *uuid.UUID
	Action     string
	EntityType string
	EntityID   *uuid.UUID
	Details    json.RawMessage
	IPAddress  string
}
