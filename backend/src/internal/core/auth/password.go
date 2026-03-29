package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 2
	argonKeyLen  uint32 = 32
)

var randRead = rand.Read

// HashPassword hashes a password using Argon2id.
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password required")
	}
	password = applyPepper(password)
	salt := make([]byte, 16)
	if _, err := randRead(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads, encodedSalt, encodedHash), nil
}

// VerifyPassword verifies a password against an Argon2id hash.
func VerifyPassword(password string, encodedHash string) (bool, error) {
	if strings.TrimSpace(password) == "" || strings.TrimSpace(encodedHash) == "" {
		return false, errors.New("password and hash required")
	}
	password = applyPepper(password)

	parts := strings.Split(encodedHash, "$")
	if len(parts) < 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid hash format")
	}

	var memory uint32
	var time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("parse params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(hash, expected) == 1 {
		return true, nil
	}
	return false, nil
}

func applyPepper(value string) string {
	pepper := strings.TrimSpace(os.Getenv("AUTH_PEPPER"))
	if pepper == "" {
		return value
	}
	return value + ":" + pepper
}
