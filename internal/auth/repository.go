package auth

import (
	"context"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

type repo struct {
	db db.Executor
}

var _ Repository = (*repo)(nil)

func NewRepository(executor db.Executor) Repository {
	return &repo{db: executor}
}

func (r *repo) Verify(ctx context.Context, userID string) error {
	const query = "UPDATE users SET verified_at = NOW() WHERE id = $1 AND verified_at IS NULL"

	res, err := r.db.ExecContext(ctx, query, userID)
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

func (r *repo) ChangePassword(ctx context.Context, userID, passwordHash string) error {
	const query = "UPDATE users SET password_hash = $1 WHERE id = $2"

	res, err := r.db.ExecContext(ctx, query, passwordHash, userID)
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
