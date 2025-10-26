package auth

import (
	"context"
	"fmt"
)

type ctxKey int

const userCtxKey ctxKey = iota + 1

// ContextWithUser returns a new context containing the authenticated user's ID.
//
//nolint:ireturn // returning context.Context is intentional: it's the standard context type
func ContextWithUser(baseCtx context.Context, userID string) context.Context {
	return context.WithValue(baseCtx, userCtxKey, userID)
}

// UserFromContext extracts the user ID from the context.
// It returns an error if the user ID is missing or not a string.
func UserFromContext(ctx context.Context) (string, error) {
	val := ctx.Value(userCtxKey)

	if val == nil {
		return "", fmt.Errorf("no user ID in context")
	}

	userID, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("user ID is not a string: %T", val)
	}

	return userID, nil
}
