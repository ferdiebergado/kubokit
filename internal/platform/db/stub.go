package db

import (
	"context"
	"errors"
)

type StubTxManager struct {
	RunInTxFunc func(context.Context, func(Executor) error) error
}

func (s *StubTxManager) RunInTx(ctx context.Context, fn func(tx Executor) error) error {
	if s.RunInTxFunc == nil {
		return errors.New("RunInTx not implemented by StubTxManager")
	}

	return s.RunInTxFunc(ctx, fn)
}
