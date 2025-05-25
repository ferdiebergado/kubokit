package auth

import (
	"context"
	"database/sql"

	"github.com/ferdiebergado/kubokit/internal/user"
)

type Repository struct {
	DB *sql.DB
}

const QueryUserCreate = `
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id, email, created_at, updated_at
`

func (r *Repository) CreateUser(ctx context.Context, params CreateUserParams) (user.User, error) {
	row := r.DB.QueryRowContext(ctx, QueryUserCreate, params.Email, params.PasswordHash)
	var u user.User
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return user.User{}, err
	}
	return u, nil
}

const QueryUserFindByEmail = `
SELECT id, email, password_hash, created_at, updated_at, verified_at FROM users
WHERE email = $1
LIMIT 1
`

func (r *Repository) FindUserByEmail(ctx context.Context, email string) (user.User, error) {
	var u user.User
	row := r.DB.QueryRowContext(ctx, QueryUserFindByEmail, email)
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		return user.User{}, err
	}
	return u, nil
}

const QueryUserVerify = `
UPDATE users
SET verified_at = NOW()
WHERE id = $1
`

func (r *Repository) VerifyUser(ctx context.Context, userID string) error {
	_, err := r.DB.ExecContext(ctx, QueryUserVerify, userID)
	if err != nil {
		return err
	}
	return nil
}

const QueryUserList = "SELECT id, email, verified_at, created_at, updated_at FROM users"

func (r *Repository) ListUsers(ctx context.Context) ([]user.User, error) {
	rows, err := r.DB.QueryContext(ctx, QueryUserList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []user.User
	for rows.Next() {
		var u user.User
		if err := rows.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	if err := rows.Close(); err != nil {
		return nil, err
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

const queryUserChangePassword = "UPDATE users SET password_hash = $1 WHERE email = $2"

func (r *Repository) ChangeUserPassword(ctx context.Context, email, newPassword string) error {
	res, err := r.DB.ExecContext(ctx, queryUserChangePassword, newPassword, email)
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
