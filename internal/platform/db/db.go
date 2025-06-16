package db

import (
	"context"
	"database/sql"
)

type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type TxManager interface {
	// RunInTx executes the given function within a database transaction.
	// It begins a transaction, calls the function with a new context
	// containing the transaction, and then commits or rolls back
	// based on the function's return value.
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}
