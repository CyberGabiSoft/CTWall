package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// SessionClaims defines the JWT claims used in CTWall sessions.
type SessionClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

var parseSessionClaims = func(token string, claims *SessionClaims, secret []byte) (*jwt.Token, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	return parser.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return secret, nil
	})
}

// NewSessionToken generates a signed JWT for a user.
func NewSessionToken(userID uuid.UUID, role Role, ttl time.Duration, secret []byte, issuer string) (string, error) {
	if userID == uuid.Nil || role == "" {
		return "", errors.New("invalid user payload")
	}
	if len(secret) == 0 {
		return "", errors.New("secret required")
	}
	now := time.Now().UTC()
	claims := SessionClaims{
		Role: string(role),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ParseSessionToken validates and parses a JWT session token.
func ParseSessionToken(token string, secret []byte, issuer string) (uuid.UUID, Role, error) {
	if strings.TrimSpace(token) == "" {
		return uuid.Nil, "", errors.New("token required")
	}
	claims := &SessionClaims{}
	parsed, err := parseSessionClaims(token, claims, secret)
	if err != nil {
		return uuid.Nil, "", err
	}
	if !parsed.Valid {
		return uuid.Nil, "", errors.New("invalid token")
	}
	if issuer != "" && claims.Issuer != issuer {
		return uuid.Nil, "", fmt.Errorf("unexpected issuer")
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid subject")
	}
	role := NormalizeRole(claims.Role)
	if !IsValidRole(string(role)) {
		return uuid.Nil, "", fmt.Errorf("invalid role")
	}
	return userID, role, nil
}
