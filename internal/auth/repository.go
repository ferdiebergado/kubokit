package auth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

var _ AuthRepository = &Repository{}

type Repository struct {
	db db.Executor
}

func (r *Repository) VerifyUser(ctx context.Context, userID string) error {
	const query = "UPDATE users SET verified_at = NOW() WHERE id = $1 AND verified_at IS NULL"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}

	res, err := executor.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("query to verify user with ID %s: %w: %w", userID, db.ErrQueryFailed, err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected by verification of user with ID %s: %w: %w", userID, db.ErrQueryFailed, err)
	}

	if numRows == 0 {
		return fmt.Errorf("user with ID %s not found or user is already verified: %w", userID, user.ErrNotFound)
	}

	return nil
}

func (r *Repository) ChangeUserPassword(ctx context.Context, email, passwordHash string) error {
	const query = "UPDATE users SET password_hash = $1 WHERE email = $2"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}

	res, err := executor.ExecContext(ctx, query, passwordHash, email)
	if err != nil {
		return fmt.Errorf("query to change password: %w: %w", db.ErrQueryFailed, err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected by password change: %w: %w", db.ErrQueryFailed, err)
	}

	if numRows == 0 {
		return user.ErrNotFound
	}

	return nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
