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

const QueryUserVerify = `
UPDATE users
SET verified_at = NOW()
WHERE id = $1
`

func (r *Repository) VerifyUser(ctx context.Context, userID string) error {
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}

	res, err := executor.ExecContext(ctx, QueryUserVerify, userID)
	if err != nil {
		return fmt.Errorf("query to verify user with ID %s: %w", userID, err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected by verification of user with ID %s: %w", userID, err)
	}

	if numRows == 0 {
		return fmt.Errorf("user with ID %s not found: %w", userID, user.ErrNotFound)
	}

	return nil
}

//nolint:gosec //G101: No credentials are hardcoded.
const queryUserChangePassword = "UPDATE users SET password_hash = $1 WHERE email = $2"

func (r *Repository) ChangeUserPassword(ctx context.Context, email, passwordHash string) error {
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}

	res, err := executor.ExecContext(ctx, queryUserChangePassword, passwordHash, email)
	if err != nil {
		return fmt.Errorf("query to change password: %w", err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected by password change: %w", err)
	}

	if numRows == 0 {
		return user.ErrNotFound
	}

	return nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
