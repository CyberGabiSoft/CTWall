package auth

import "strings"

// AccountType defines the classification for a user account.
type AccountType string

const (
	AccountTypeUser           AccountType = "USER"
	AccountTypeServiceAccount AccountType = "SERVICE_ACCOUNT"
)

// NormalizeAccountType returns the canonical account type value.
func NormalizeAccountType(value string) AccountType {
	return AccountType(strings.ToUpper(strings.TrimSpace(value)))
}

// IsValidAccountType reports whether the account type is one of the known values.
func IsValidAccountType(value string) bool {
	switch NormalizeAccountType(value) {
	case AccountTypeUser, AccountTypeServiceAccount:
		return true
	default:
		return false
	}
}
