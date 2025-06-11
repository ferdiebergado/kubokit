package web

import (
	"context"
	"fmt"
)

type ctxKey int

const paramsCtxKey ctxKey = iota

//nolint:ireturn //This function needs to return a context.
func NewContextWithParams(baseCtx context.Context, params any) context.Context {
	return context.WithValue(baseCtx, paramsCtxKey, params)
}

// nolint: ireturn //This is a generic function.
func ParamsFromContext[T any](ctx context.Context) (T, error) {
	val := ctx.Value(paramsCtxKey)
	params, ok := val.(T)
	if !ok {
		var t T
		return t, fmt.Errorf("params: %v is not a %T", val, t)
	}
	return params, nil
}
