package user

import (
	"context"
	"fmt"
)

type ctxKey int

const userCtxKey ctxKey = iota

func NewContextWithUser(baseCtx context.Context, userID string) context.Context {
	return context.WithValue(baseCtx, userCtxKey, userID)
}

func FromContext(ctx context.Context) (string, error) {
	val := ctx.Value(userCtxKey)
	userID, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("%v is not a string", val)
	}

	return userID, nil
}
