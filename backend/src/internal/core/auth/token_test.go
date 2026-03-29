package auth

import "testing"

func TestHashAPIToken(t *testing.T) {
	if HashAPIToken("") != "" {
		t.Fatalf("expected empty hash")
	}
	hash := HashAPIToken("token")
	if hash == "" {
		t.Fatalf("expected hash")
	}
	if hash != HashAPIToken("token") {
		t.Fatalf("expected deterministic hash")
	}
}

func TestHashRefreshToken(t *testing.T) {
	if HashRefreshToken("") != "" {
		t.Fatalf("expected empty hash")
	}
	hash := HashRefreshToken("refresh")
	if hash == "" {
		t.Fatalf("expected hash")
	}
	if hash != HashRefreshToken("refresh") {
		t.Fatalf("expected deterministic hash")
	}
}

func TestHashTokenWithPepper(t *testing.T) {
	base := HashAPIToken("token")
	t.Setenv("AUTH_PEPPER", "pepper")
	peppered := HashAPIToken("token")
	if base == peppered {
		t.Fatalf("expected pepper to change hash")
	}
	if peppered != HashAPIToken("token") {
		t.Fatalf("expected deterministic hash with pepper")
	}
}
