package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
)

var (
	ErrNotFound  = errors.New("user not found")
	ErrDuplicate = errors.New("user already exists")
)

type repo struct {
	db db.Executor
}

var _ Repository = (*repo)(nil)

func NewRepository(db db.Executor) Repository {
	return &repo{db: db}
}

type CreateParams struct {
	Email, Password string
}

func (r *repo) Create(ctx context.Context, params CreateParams) (User, error) {
	const query = `
	INSERT INTO users (email, password_hash)
	VALUES ($1, $2)
	RETURNING id, email, created_at, updated_at
	`

	row := r.db.QueryRowContext(ctx, query, params.Email, params.Password)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil && !errors.Is(err, sql.ErrNoRows) {
		const errFmt = "execute query: %w"
		if db.IsUniqueConstraintViolation(err) {
			return User{}, fmt.Errorf(errFmt, ErrDuplicate)
		}
		return User{}, fmt.Errorf(errFmt, err)
	}
	return u, nil
}

func (r *repo) FindByEmail(ctx context.Context, email string) (*User, error) {
	const query = `
	SELECT id, email, password_hash, created_at, updated_at, verified_at
	FROM users
	WHERE email = $1
	`

	row := r.db.QueryRowContext(ctx, query, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("execute query: %w", err)
	}
	return &u, nil
}

func (r *repo) List(ctx context.Context) ([]User, error) {
	const query = "SELECT id, email, verified_at, created_at, updated_at FROM users"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("repo list all users: %w", err)
	}
	defer rows.Close()

	//nolint:prealloc //Cannot identify the length of the rows without running another query.
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("execute query: %w", err)
		}
		users = append(users, u)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close rows: %w", err)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("get iteration error: %w", err)
	}

	return users, nil
}

func (r *repo) Find(ctx context.Context, userID string) (*User, error) {
	const query = "SELECT id, email, verified_at, created_at, updated_at FROM users WHERE id = $1"

	row := r.db.QueryRowContext(ctx, query, userID)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("execute query: %w", err)
	}
	return &u, nil
}

func (r *repo) Delete(ctx context.Context, userID string) error {
	const query = "DELETE FROM users WHERE id = $1"

	res, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
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

	res, err := r.db.ExecContext(ctx, query, updates.PasswordHash, updates.VerifiedAt, userID)
	if err != nil {
		return fmt.Errorf("execute query: %w", err)
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
