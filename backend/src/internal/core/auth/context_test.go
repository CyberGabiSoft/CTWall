package auth

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestUserContextRoundTrip(t *testing.T) {
	user := UserContext{
		ID:          uuid.New(),
		Role:        RoleAdmin,
		AccountType: AccountTypeUser,
		Email:       "user@example.com",
		FullName:    "User",
		AuthMethod:  "cookie",
	}
	ctx := WithUser(context.Background(), user)
	got, ok := UserFromContext(ctx)
	if !ok {
		t.Fatalf("expected user context")
	}
	if got.ID != user.ID || got.Role != user.Role {
		t.Fatalf("unexpected user context")
	}
}

func TestUserContextMissing(t *testing.T) {
	if _, ok := UserFromContext(context.Background()); ok {
		t.Fatalf("expected missing user context")
	}
}
