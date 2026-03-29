package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestSessionToken(t *testing.T) {
	userID := uuid.New()
	secret := []byte("secret")
	token, err := NewSessionToken(userID, RoleAdmin, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	gotID, gotRole, err := ParseSessionToken(token, secret, "issuer")
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if gotID != userID || gotRole != RoleAdmin {
		t.Fatalf("unexpected token claims")
	}
}

func TestSessionTokenInvalid(t *testing.T) {
	userID := uuid.New()
	secret := []byte("secret")
	token, err := NewSessionToken(userID, RoleAdmin, time.Minute, secret, "issuer")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, _, err := ParseSessionToken(token, []byte("bad"), "issuer"); err == nil {
		t.Fatalf("expected invalid secret error")
	}
	if _, _, err := ParseSessionToken(token, secret, "other"); err == nil {
		t.Fatalf("expected issuer error")
	}
}

func TestSessionTokenInvalidInputs(t *testing.T) {
	if _, err := NewSessionToken(uuid.Nil, RoleAdmin, time.Minute, []byte("secret"), ""); err == nil {
		t.Fatalf("expected error for nil user")
	}
	if _, err := NewSessionToken(uuid.New(), "", time.Minute, []byte("secret"), ""); err == nil {
		t.Fatalf("expected error for empty role")
	}
	if _, err := NewSessionToken(uuid.New(), RoleAdmin, time.Minute, nil, ""); err == nil {
		t.Fatalf("expected error for empty secret")
	}
	if _, _, err := ParseSessionToken(" ", []byte("secret"), ""); err == nil {
		t.Fatalf("expected error for empty token")
	}
}

func TestSessionTokenInvalidClaims(t *testing.T) {
	userID := uuid.New()
	secret := []byte("secret")
	token, err := NewSessionToken(userID, Role("BAD_ROLE"), time.Minute, secret, "")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, _, err := ParseSessionToken(token, secret, ""); err == nil {
		t.Fatalf("expected invalid role error")
	}
}

func TestSessionTokenInvalidSubject(t *testing.T) {
	claims := SessionClaims{
		Role: string(RoleAdmin),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "not-a-uuid",
			Issuer:    "issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("signed token: %v", err)
	}
	if _, _, err := ParseSessionToken(signed, []byte("secret"), "issuer"); err == nil {
		t.Fatalf("expected invalid subject error")
	}
}
