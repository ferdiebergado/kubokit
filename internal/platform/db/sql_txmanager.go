package db

import (
	"context"
	"database/sql"
	"log/slog"
)

type txCtxKey int

const txKey txCtxKey = iota

func NewContextWithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, txKey, tx)
}

// TxFromContext retrieves the transaction from the context.
// It's used by repositories to get the current transaction if available.
func TxFromContext(ctx context.Context) *sql.Tx {
	if tx, ok := ctx.Value(txKey).(*sql.Tx); ok {
		return tx
	}
	return nil
}

type SQLTxManager struct {
	db *sql.DB
}

func (tm *SQLTxManager) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := tm.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	// Store the transaction in the context
	txCtx := NewContextWithTx(ctx, tx)

	// Defer rollback, it's a no-op if the transaction is committed.
	defer func() {
		if r := recover(); r != nil {
			rollback(tx)
			panic(r) // Re-throw the panic
		} else if err != nil {
			rollback(tx) // Error from fn, rollback
		} else {
			err = tx.Commit() // No error from fn, try to commit
		}
	}()

	err = fn(txCtx) // Execute the business logic with the transactional context
	return err
}

func NewSQLTxManager(db *sql.DB) *SQLTxManager {
	return &SQLTxManager{db: db}
}

func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		slog.Error("failed to rollback transaction", "reason", err)
	}
}
