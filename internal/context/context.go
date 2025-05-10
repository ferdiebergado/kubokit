package context

import "context"

type ctxKey int

const (
	userCtxKey ctxKey = iota + 1
	paramsCtxKey
)

func NewContextWithUser(baseCtx context.Context, user string) context.Context {
	return context.WithValue(baseCtx, userCtxKey, user)
}

func NewContextWithParams(baseCtx context.Context, params any) context.Context {
	return context.WithValue(baseCtx, paramsCtxKey, params)
}

func ParamsFromContext[T any](ctx context.Context) (T, bool) {
	val := ctx.Value(paramsCtxKey)
	params, ok := val.(T)
	return params, ok
}
