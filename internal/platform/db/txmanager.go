package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

type TxManager struct {
	db *sql.DB
}

func NewTxManager(db *sql.DB) *TxManager {
	return &TxManager{db: db}
}

func (t *TxManager) RunInTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

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

	err = fn(tx) // Execute the business logic with the transactional context
	return err
}

func rollback(tx *sql.Tx) {
	if err := tx.Rollback(); err != nil {
		slog.Error("failed to rollback transaction", "reason", err)
	}
}
