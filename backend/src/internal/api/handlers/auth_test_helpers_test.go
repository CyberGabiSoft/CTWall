package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"backend/internal/core/auth"
	"backend/internal/store"

	"github.com/google/uuid"
)

func withAuthedRequest(t *testing.T, st store.Store, req *http.Request) *http.Request {
	t.Helper()

	user, err := st.CreateUser(
		fmt.Sprintf("test-%s@example.com", uuid.NewString()),
		"hash",
		string(auth.RoleAdmin),
		string(auth.AccountTypeUser),
		"Test User",
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}

	ctx := auth.WithUser(req.Context(), auth.UserContext{
		ID:          user.ID,
		Email:       user.Email,
		Role:        auth.RoleAdmin,
		AccountType: auth.AccountTypeUser,
	})
	return req.WithContext(ctx)
}
