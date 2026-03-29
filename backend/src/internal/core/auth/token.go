package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
)

// HashAPIToken returns a SHA256 hash (hex) for API tokens.
func HashAPIToken(token string) string {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return ""
	}
	pepper := strings.TrimSpace(os.Getenv("AUTH_PEPPER"))
	if pepper != "" {
		trimmed = trimmed + ":" + pepper
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}

// HashRefreshToken returns a SHA256 hash (hex) for refresh tokens.
func HashRefreshToken(token string) string {
	return HashAPIToken(token)
}
