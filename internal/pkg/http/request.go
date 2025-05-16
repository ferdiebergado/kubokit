package http

import "context"

type ctxKey int

const paramsCtxKey = iota

func NewContextWithParams(baseCtx context.Context, params any) context.Context {
	return context.WithValue(baseCtx, paramsCtxKey, params)
}

func ParamsFromContext[T any](ctx context.Context) (any, T, bool) {
	val := ctx.Value(paramsCtxKey)
	params, ok := val.(T)
	return val, params, ok
}
