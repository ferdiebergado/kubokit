package user

import (
	"context"
	"database/sql"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}

const QueryUserList = "SELECT id, email, metadata, verified_at, created_at, updated_at FROM users"

func (r *Repository) GetAllUsers(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, QueryUserList)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(
			&user.ID, &user.Email, &user.Metadata, &user.VerifiedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	if err := rows.Close(); err != nil {
		return nil, err
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}
