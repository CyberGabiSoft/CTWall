package auth

import (
	"io"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestHashPasswordErrors(t *testing.T) {
	if _, err := HashPassword("   "); err == nil {
		t.Fatalf("expected empty password error")
	}

	originalRandRead := randRead
	t.Cleanup(func() {
		randRead = originalRandRead
	})
	randRead = func(_ []byte) (int, error) {
		return 0, io.ErrUnexpectedEOF
	}

	if _, err := HashPassword("secret"); err == nil {
		t.Fatalf("expected salt generation error")
	}
}

func TestVerifyPasswordParseAndDecodeErrors(t *testing.T) {
	if _, err := VerifyPassword("secret", "$argon2id$v=19$m=oops$abcd$abcd"); err == nil {
		t.Fatalf("expected parse params error")
	}
	if _, err := VerifyPassword("secret", "$argon2id$v=19$m=1,t=1,p=1$***$abcd"); err == nil {
		t.Fatalf("expected decode salt error")
	}
	if _, err := VerifyPassword("secret", "$argon2id$v=19$m=1,t=1,p=1$abcd$***"); err == nil {
		t.Fatalf("expected decode hash error")
	}
}

func TestRoleAllowedNoMatchWithAllowedRoles(t *testing.T) {
	if RoleAllowed(RoleReader, RoleAdmin, RoleWriter) {
		t.Fatalf("expected no match for role")
	}
}

func TestParseSessionTokenInvalidParsedToken(t *testing.T) {
	originalParse := parseSessionClaims
	t.Cleanup(func() {
		parseSessionClaims = originalParse
	})
	parseSessionClaims = func(_ string, _ *SessionClaims, _ []byte) (*jwt.Token, error) {
		return &jwt.Token{Valid: false}, nil
	}

	if _, _, err := ParseSessionToken("fake-token", []byte("secret"), ""); err == nil || err.Error() != "invalid token" {
		t.Fatalf("expected invalid token error, got %v", err)
	}
}
