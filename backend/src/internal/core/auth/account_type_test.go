package auth

import "testing"

func TestAccountTypeHelpers(t *testing.T) {
	if NormalizeAccountType(" user ") != AccountTypeUser {
		t.Fatalf("expected user account type normalization")
	}
	if !IsValidAccountType("USER") || !IsValidAccountType("service_account") {
		t.Fatalf("expected valid account types")
	}
	if IsValidAccountType("invalid") {
		t.Fatalf("expected invalid account type")
	}
}
