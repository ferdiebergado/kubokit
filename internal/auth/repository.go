package auth

import (
	"context"
	"database/sql"
)

var _ AuthRepository = &Repository{}

type Repository struct {
	db *sql.DB
}

const QueryUserVerify = `
UPDATE users
SET verified_at = NOW()
WHERE id = $1
`

func (r *Repository) VerifyUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, QueryUserVerify, userID)
	if err != nil {
		return err
	}
	return nil
}

//nolint:gosec //G101: No credentials are hardcoded.
const queryUserChangePassword = "UPDATE users SET password_hash = $1 WHERE email = $2"

func (r *Repository) ChangeUserPassword(ctx context.Context, email, newPassword string) error {
	res, err := r.db.ExecContext(ctx, queryUserChangePassword, newPassword, email)
	if err != nil {
		return err
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if numRows == 0 {
		return ErrUserNotFound
	}

	return nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
