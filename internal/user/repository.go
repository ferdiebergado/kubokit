package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var _ UserRepository = &Repository{}

var (
	ErrNotFound            = errors.New("user repository: user not found")
	ErrQueryFailed         = errors.New("user repository: query failed")
	ErrConstraintViolation = errors.New("user repository: constraint violation")
)

type Repository struct {
	db *sql.DB
}

type CreateUserParams struct {
	Email        string
	PasswordHash string
}

const QueryUserCreate = `
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id, email, created_at, updated_at
`

func (r *Repository) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	row := r.db.QueryRowContext(ctx, QueryUserCreate, params.Email, params.PasswordHash)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return u, fmt.Errorf("%w: create user with email %s: %v", ErrQueryFailed, params.Email, err)
	}
	return u, nil
}

const QueryUserFindByEmail = `
SELECT id, email, password_hash, created_at, updated_at, verified_at FROM users
WHERE email = $1
LIMIT 1
`

func (r *Repository) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	row := r.db.QueryRowContext(ctx, QueryUserFindByEmail, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: find user with email %s: %v", ErrQueryFailed, email, err)
	}
	return &u, nil
}

const QueryUserList = "SELECT id, email, verified_at, created_at, updated_at FROM users"

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, QueryUserList)
	if err != nil {
		return nil, fmt.Errorf("%w: list users: %v", ErrQueryFailed, err)
	}
	defer rows.Close()

	//nolint:prealloc //Cannot identify the length of the rows without running another query.
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("user repository: scan row: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("user repository: close user rows: %w", err)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user repository: iterate over user rows: %w", err)
	}

	return users, nil
}

const QueryFindUser = "SELECT id, email, verified_at, created_at, updated_at FROM users WHERE id = $1"

func (r *Repository) FindUser(ctx context.Context, userID string) (User, error) {
	row := r.db.QueryRowContext(ctx, QueryFindUser, userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return u, fmt.Errorf("%w: find user with id %s: %v", ErrQueryFailed, userID, err)
	}
	return u, nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
