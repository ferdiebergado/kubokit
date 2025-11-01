package auth

import (
	"context"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

type SQLRepository struct {
	db db.Executor
}

func NewRepository(db db.Executor) *SQLRepository {
	return &SQLRepository{db: db}
}

var _ Repository = (*SQLRepository)(nil)

func (r *SQLRepository) Verify(ctx context.Context, userID string) error {
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

func (r *SQLRepository) ChangePassword(ctx context.Context, userID, passwordHash string) error {
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
