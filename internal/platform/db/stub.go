package db

import (
	"context"
	"fmt"
)

type StubTxManager struct {
	RunInTxFunc func(ctx context.Context, fn func(ctx context.Context) error) error
}

// RunInTx executes the given function within a database transaction.
// It begins a transaction, calls the function with a new context
// containing the transaction, and then commits or rolls back
// based on the function's return value.
func (s *StubTxManager) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if s.RunInTxFunc == nil {
		return fmt.Errorf("RunInTx not implemented by stub")
	}
	return s.RunInTxFunc(ctx, fn)
}
