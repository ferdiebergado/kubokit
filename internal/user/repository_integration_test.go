//go:build integration

package user_test

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	mockUserID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	mockEmail  = "alice@example.com"
)

func TestIntegrationRepository_List(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)

	users, err := repo.List(t.Context())
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}

	gotLen, wantLen := len(users), len(mockUsers)
	if gotLen != wantLen {
		t.Fatalf("len(users) = %d, want: %d", gotLen, wantLen)
	}

	for i, u := range users {
		if !reflect.DeepEqual(u, mockUsers[i]) {
			t.Errorf("u = %+v, want: %+v", u, mockUsers[i])
		}
	}
}

func setup(t *testing.T) ([]user.User, *sql.Tx) {
	t.Helper()

	const (
		numUsers = 3

		seedQuery = `
		INSERT INTO users (email, password_hash)
		VALUES
		('abc@example.com', 'hashed1'),
		('123@example.com', 'hashed2'),
		('user1@example.com', 'hashed3')`

		usersQuery = `
		SELECT id, email, metadata, verified_at, created_at, updated_at
		FROM users`
	)

	_, tx := db.Setup(t)
	ctx := t.Context()

	_, err := tx.ExecContext(ctx, seedQuery)
	if err != nil {
		t.Fatalf("failed to seed users: %v", err)
	}

	rows, err := tx.QueryContext(ctx, usersQuery)
	if err != nil {
		t.Fatalf("failed to retrieve users: %v", err)
	}
	defer rows.Close()

	users := make([]user.User, 0, numUsers)
	for rows.Next() {
		var u user.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Metadata, &u.VerifiedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			t.Fatalf("failed to scan row: %v", err)
		}

		users = append(users, u)
	}

	if err := rows.Close(); err != nil {
		t.Fatalf("failed to close rows: %v", err)
	}

	if err := rows.Err(); err != nil {
		t.Fatalf("failed to iterate rows: %v", err)
	}

	return users, tx
}

func TestIntegrationRepository_FindReturnsUser(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)

	wantUser := mockUsers[0]

	u, err := repo.Find(t.Context(), wantUser.ID)
	if err != nil {
		t.Fatalf("failed to find user with id: %q: %v", wantUser.ID, err)
	}

	if !reflect.DeepEqual(u, &wantUser) {
		t.Errorf("repo.Find(t.Context(), %q) = %+v, want: %+v", wantUser.ID, u, &wantUser)
	}
}

func TestIntegrationRepository_FindUserDontExistFails(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := user.NewRepository(tx)

	_, err := repo.Find(t.Context(), mockUserID)
	if err == nil {
		t.Fatal("repo.Find did not return an error")
	}

	if !errors.Is(err, user.ErrNotFound) {
		t.Errorf("repo.Find(t.Context(), %q) = %v, want: %v", mockUserID, err, user.ErrNotFound)
	}
}

func TestIntegrationRepository_FindByEmail(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)
	wantUser := mockUsers[0]

	u, err := repo.FindByEmail(t.Context(), wantUser.Email)
	if err != nil {
		t.Fatalf("failed to find user by email: %v", err)
	}

	u.PasswordHash = ""

	if !reflect.DeepEqual(u, &wantUser) {
		t.Errorf("repo.FindUserByEmail(txCtx, %q) = %+v, want: %+v", wantUser.Email, u, &wantUser)
	}
}

func TestIntegrationRepository_Create(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params user.CreateParams
		err    error
	}{
		{
			name: "User is available",
			params: user.CreateParams{
				Email:    "agnis@example.com",
				Password: "hashed",
			},
		},
		{
			name: "duplicate user should return error",
			params: user.CreateParams{
				Email:    "agnis@example.com",
				Password: "hashed",
			},
			err: user.ErrDuplicate,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, tx := setup(t)
			ctx := context.Background()

			repo := user.NewRepository(tx)
			u, err := repo.Create(ctx, tc.params)
			if err != nil {
				if tc.err == nil {
					t.Fatalf("failed to create user: %v", err)
				}

				if !errors.Is(err, tc.err) {
					t.Errorf("repo.Create(txCtx, tc.params) = %v, want: %v", err, tc.err)
				}
			} else {
				gotEmail, wantEmail := u.Email, tc.params.Email
				if gotEmail != wantEmail {
					t.Errorf("u.Email = %q, want: %q", gotEmail, wantEmail)
				}

				if u.CreatedAt.IsZero() {
					t.Errorf("u.CreatedAt = %v, want: non-zero", u.CreatedAt)
				}

				if u.UpdatedAt.IsZero() {
					t.Errorf("u.UpdatedAt = %v, want: non-zero", u.UpdatedAt)
				}
			}
		})
	}
}

func TestIntegrationRepository_Delete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, userID string
		err          error
	}{
		{
			name:   "Delete an existing user",
			userID: "6f1e3e3a-1c55-4f19-8341-8132f374dc5f",
		},
		{
			name:   "Delete a user that does not exists",
			userID: "6f1e3e3a-1c55-4f19-8341-8132f374dc50",
			err:    user.ErrNotFound,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, tx := setup(t)
			userRepo := user.NewRepository(tx)
			err := userRepo.Delete(ctx, tc.userID)
			if err != nil {
				if tc.err == nil {
					t.Fatalf("failed to delete user: %v", err)
				}

				if err != tc.err {
					t.Errorf("repo.Delete(txCtx, %q) = %v, want: %v", tc.userID, err, tc.err)
				}
			}
			const query = "SELECT email FROM users WHERE id = $1"
			row := tx.QueryRow(query, tc.userID)
			var email string
			if err := row.Scan(&email); err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					t.Errorf("tx.QueryRow(%q, %q) = %v, want: %v", query, tc.userID, err, sql.ErrNoRows)
				}
			}
		})
	}
}

func TestIntegrationRepository_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, tx := setup(t)

	userRepo := user.NewRepository(tx)
	currentTimestamp := time.Now().Truncate(time.Microsecond)
	updates := &user.User{
		VerifiedAt: &currentTimestamp,
	}
	if err := userRepo.Update(ctx, updates, mockUserID); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	const query = "SELECT id, verified_at, password_hash, updated_at, created_at, email FROM users WHERE id = $1"
	row := tx.QueryRow(query, mockUserID)
	var updatedUser user.User
	if err := row.Scan(&updatedUser.ID, &updatedUser.VerifiedAt, &updatedUser.PasswordHash, &updatedUser.UpdatedAt, &updatedUser.CreatedAt, &updatedUser.Email); err != nil {
		t.Fatal(err)
	}
	gotVerifiedAt := updatedUser.VerifiedAt
	if !gotVerifiedAt.Equal(currentTimestamp) {
		t.Errorf("updatedUser.VerifiedAt = %v, want: %v", gotVerifiedAt, currentTimestamp)
	}

	gotUpdatedAt := updatedUser.UpdatedAt.Truncate(time.Second)
	wantUpdatedAt := currentTimestamp.Truncate(time.Second)
	if !gotUpdatedAt.Equal(wantUpdatedAt) {
		t.Errorf("updatedUser.UpdatedAt = %v, want: %v", gotUpdatedAt, wantUpdatedAt)
	}

	gotHash := updatedUser.PasswordHash
	wantHash := "$2a$10$e0MYzXyjpJS7Pd0RVvHwHeFx4fQnhdQnZZF9uG6x1Z1ZzR12uLh9e"

	if gotHash == "" {
		t.Errorf("updatedUser.PasswordHash = %q, want: %q", gotHash, wantHash)
	}

	gotID := updatedUser.ID
	wantID := mockUserID
	if gotID != wantID {
		t.Errorf("updatedUser.ID = %q, want: %q", gotID, wantID)
	}

	gotCreatedAt := updatedUser.CreatedAt
	wantCreatedAt := time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local)
	if !gotCreatedAt.Equal(wantCreatedAt) {
		t.Errorf("updatedUser.CreatedAt = %v, want: %v", gotCreatedAt, wantCreatedAt)
	}

	gotEmail := updatedUser.Email
	wantEmail := "alice@example.com"

	if gotEmail != wantEmail {
		t.Errorf("updatedUser.Email = %q, want: %q", gotEmail, wantEmail)
	}
}
