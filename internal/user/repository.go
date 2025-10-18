package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

var ErrNotFound = errors.New("user not found")

type repo struct {
	db db.Executor
}

type CreateUserParams struct {
	Email, Password string
}

func (r *repo) Create(ctx context.Context, params CreateUserParams) (User, error) {
	const query = `
	INSERT INTO users (email, password_hash)
	VALUES ($1, $2)
	RETURNING id, email, created_at, updated_at
	`
	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	row := executor.QueryRowContext(ctx, query, params.Email, params.Password)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		if db.IsUniqueConstraintViolation(err) {
			return u, db.ErrUniqueConstraintViolation
		}
		return u, fmt.Errorf("query to create user: %w", err)
	}
	return u, nil
}

func (r *repo) FindByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
	SELECT id, email, password_hash, created_at, updated_at, verified_at
	FROM users
	WHERE email = $1
	`
	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	row := executor.QueryRowContext(ctx, query, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("query to find user by email: %w", err)
	}
	return &u, nil
}

func (r *repo) List(ctx context.Context) ([]User, error) {
	const query = "SELECT id, email, verified_at, created_at, updated_at FROM users"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	rows, err := executor.QueryContext(ctx, query)
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

func (r *repo) Find(ctx context.Context, userID string) (*User, error) {
	const query = "SELECT id, email, verified_at, created_at, updated_at FROM users WHERE id = $1"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	row := executor.QueryRowContext(ctx, query, userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, fmt.Errorf("query to find user with id %s: %w", userID, err)
	}
	return &u, nil
}

func (r *repo) Delete(ctx context.Context, userID string) error {
	const query = "DELETE FROM users WHERE id = $1"

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	res, err := executor.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("query to delete user: %w", err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if numRows == 0 {
		return ErrNotFound
	}

	return nil
}

func (r *repo) Update(ctx context.Context, updates *User, userID string) error {
	// TODO: update metadata
	const query = `
	UPDATE users
	SET
	password_hash = COALESCE(NULLIF($1, ''), password_hash),
	verified_at = COALESCE($2, verified_at)
	WHERE id = $3`

	executor := r.db
	if tx := db.TxFromContext(ctx); tx != nil {
		executor = tx
	}
	res, err := executor.ExecContext(ctx, query, updates.PasswordHash, updates.VerifiedAt, userID)
	if err != nil {
		return fmt.Errorf("query to update user: %w", err)
	}

	numRows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}

	if numRows == 0 {
		return ErrNotFound
	}

	return nil
}

func NewRepository(db *sql.DB) *repo {
	return &repo{db}
}

var _ Repository = &repo{}
