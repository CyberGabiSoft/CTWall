package auth

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	ok, err := VerifyPassword("secret", hash)
	if err != nil || !ok {
		t.Fatalf("expected password to verify")
	}
	ok, err = VerifyPassword("wrong", hash)
	if err != nil {
		t.Fatalf("expected verify to succeed with false")
	}
	if ok {
		t.Fatalf("expected password mismatch")
	}
}

func TestVerifyPasswordInvalid(t *testing.T) {
	if _, err := VerifyPassword("", ""); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := VerifyPassword("secret", "bad-hash"); err == nil {
		t.Fatalf("expected invalid hash error")
	}
}

func TestPasswordPepper(t *testing.T) {
	t.Setenv("AUTH_PEPPER", "pepper")
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	ok, err := VerifyPassword("secret", hash)
	if err != nil || !ok {
		t.Fatalf("expected password to verify with pepper")
	}

	t.Setenv("AUTH_PEPPER", "")
	ok, err = VerifyPassword("secret", hash)
	if err != nil {
		t.Fatalf("expected verify to succeed with false")
	}
	if ok {
		t.Fatalf("expected pepper mismatch")
	}
}
