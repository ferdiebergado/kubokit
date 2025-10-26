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

func ParamsFromContext[T any](ctx context.Context) (T, error) {
	var t T
	val := ctx.Value(paramsCtxKey)
	if val == nil {
		return t, fmt.Errorf("no params in context")
	}

	params, ok := val.(T)
	if !ok {
		return t, fmt.Errorf("params is not the specified type: %T", val)
	}
	return params, nil
}
