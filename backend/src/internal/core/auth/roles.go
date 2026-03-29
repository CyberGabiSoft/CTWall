package auth

import "strings"

// Role defines the authorization role for a user.
type Role string

const (
	RoleAdmin  Role = "ADMIN"
	RoleWriter Role = "WRITER"
	RoleReader Role = "READER"
	RoleNone   Role = "NONE"
)

// NormalizeRole returns the canonical role value.
func NormalizeRole(value string) Role {
	return Role(strings.ToUpper(strings.TrimSpace(value)))
}

// IsValidRole reports whether the role is one of the known values.
func IsValidRole(value string) bool {
	switch NormalizeRole(value) {
	case RoleAdmin, RoleWriter, RoleReader, RoleNone:
		return true
	default:
		return false
	}
}

// RoleAllowed checks whether a role is in the allowed set.
func RoleAllowed(role Role, allowed ...Role) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, candidate := range allowed {
		if role == candidate {
			return true
		}
	}
	return false
}

// AllRoles returns all roles for convenience.
func AllRoles() []Role {
	return []Role{RoleAdmin, RoleWriter, RoleReader, RoleNone}
}
