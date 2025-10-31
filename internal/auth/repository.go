package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

type repo struct {
	db db.Executor
}

func NewRepository(db *sql.DB) *repo {
	return &repo{db}
}

var _ Repository = &repo{}

func (r *repo) Verify(ctx context.Context, userID string) error {
	const query = "UPDATE users SET verified_at = NOW() WHERE id = $1 AND verified_at IS NULL"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}

	res, err := executor.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if numRows == 0 {
		return fmt.Errorf("user not found or already verified: %w", ErrUserNotFound)
	}

	return nil
}

func (r *repo) ChangePassword(ctx context.Context, email, passwordHash string) error {
	const query = "UPDATE users SET password_hash = $1 WHERE email = $2"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}

	res, err := executor.ExecContext(ctx, query, passwordHash, email)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if numRows == 0 {
		return ErrUserNotFound
	}

	return nil
}
