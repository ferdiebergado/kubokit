package user

import "context"

type ctxKey int

const userCtxKey ctxKey = iota

func NewContextWithUser(baseCtx context.Context, userID string) context.Context {
	return context.WithValue(baseCtx, userCtxKey, userID)
}
