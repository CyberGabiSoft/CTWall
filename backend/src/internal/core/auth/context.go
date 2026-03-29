package auth

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey int

const userKey ctxKey = iota

// UserContext carries authenticated user details.
type UserContext struct {
	ID          uuid.UUID
	Role        Role
	AccountType AccountType
	Email       string
	Nickname    string
	FullName    string
	AuthMethod  string
	TokenID     *uuid.UUID
}

// WithUser stores the user context in a parent context.
func WithUser(ctx context.Context, user UserContext) context.Context {
	return context.WithValue(ctx, userKey, user)
}

// UserFromContext returns the user context if present.
func UserFromContext(ctx context.Context) (UserContext, bool) {
	value := ctx.Value(userKey)
	user, ok := value.(UserContext)
	return user, ok
}
