package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

var _ UserRepository = &Repository{}

var ErrUserNotFound = errors.New("user not found")

type Repository struct {
	db db.Querier
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
		return u, fmt.Errorf("query to create user with email %s: %w", params.Email, err)
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
			return nil, fmt.Errorf("user with email %s not found: %w", email, ErrUserNotFound)
		}
		return nil, fmt.Errorf("query to find user with email %s: %w", email, err)
	}
	return &u, nil
}

const QueryUserList = "SELECT id, email, verified_at, created_at, updated_at FROM users"

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, QueryUserList)
	if err != nil {
		return nil, fmt.Errorf("query to list all users: %w", err)
	}
	defer rows.Close()

	//nolint:prealloc //Cannot identify the length of the rows without running another query.
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan row to list users: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close rows to list users: %w", err)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows to list users: %w", err)
	}

	return users, nil
}

const QueryFindUser = "SELECT id, email, verified_at, created_at, updated_at FROM users WHERE id = $1"

func (r *Repository) FindUser(ctx context.Context, userID string) (User, error) {
	row := r.db.QueryRowContext(ctx, QueryFindUser, userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return u, fmt.Errorf("query to find user with id %s: %w", userID, err)
	}
	return u, nil
}

func NewRepository(db db.Querier) *Repository {
	return &Repository{db}
}
