package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

var _ UserRepository = &Repository{}

var ErrNotFound = errors.New("user not found")

type Repository struct {
	db db.Executor
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
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}
	row := executor.QueryRowContext(ctx, QueryUserCreate, params.Email, params.PasswordHash)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return u, fmt.Errorf("query to create user: %w", err)
	}
	return u, nil
}

const QueryUserFindByEmail = `
SELECT id, email, password_hash, created_at, updated_at, verified_at FROM users
WHERE email = $1
LIMIT 1
`

func (r *Repository) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}
	row := executor.QueryRowContext(ctx, QueryUserFindByEmail, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query to find user by email: %w", err)
	}
	return &u, nil
}

const QueryUserList = "SELECT id, email, verified_at, created_at, updated_at FROM users"

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}
	rows, err := executor.QueryContext(ctx, QueryUserList)
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
	// Get the current executor (either *sql.DB or *sql.Tx from context)
	executor := r.db // Default to *sql.DB
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx // Use the transaction if present in context
	}
	row := executor.QueryRowContext(ctx, QueryFindUser, userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return u, fmt.Errorf("query to find user with id %s: %w", userID, err)
	}
	return u, nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
