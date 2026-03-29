package auth

import "testing"

func TestRolesHelpers(t *testing.T) {
	if NormalizeRole(" admin ") != RoleAdmin {
		t.Fatalf("expected admin role normalization")
	}
	if !IsValidRole("writer") || !IsValidRole("READER") || !IsValidRole("none") {
		t.Fatalf("expected valid roles")
	}
	if IsValidRole("unknown") {
		t.Fatalf("expected invalid role")
	}
	if RoleAllowed(RoleWriter) {
		t.Fatalf("expected RoleAllowed to be false with no allowed roles")
	}
	if !RoleAllowed(RoleWriter, RoleAdmin, RoleWriter) {
		t.Fatalf("expected RoleAllowed to match")
	}
	all := AllRoles()
	if len(all) != 4 {
		t.Fatalf("expected 4 roles")
	}
}
