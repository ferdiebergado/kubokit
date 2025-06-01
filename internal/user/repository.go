package user

import (
	"context"
	"database/sql"
)

var _ UserRepository = &Repository{}

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
	if err := row.Scan(&u.ID, &u.Email, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return u, err
	}
	return u, nil
}

const QueryUserFindByEmail = `
SELECT id, email, password_hash, created_at, updated_at, verified_at FROM users
WHERE email = $1
LIMIT 1
`

func (r *Repository) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row := r.db.QueryRowContext(ctx, QueryUserFindByEmail, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt, &u.UpdatedAt, &u.VerifiedAt); err != nil {
		return User{}, err
	}
	return u, nil
}

const QueryUserList = "SELECT id, email, verified_at, created_at, updated_at FROM users"

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, QueryUserList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	//nolint:prealloc //Cannot identify the length of the rows without running another query.
	var users []User
	for rows.Next() {
		var u User
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

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db}
}
