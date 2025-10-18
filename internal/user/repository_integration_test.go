//go:build integration

package user_test

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const querySeedUsers = `
INSERT INTO users (id, email, password_hash, verified_at, metadata, created_at, updated_at, deleted_at) VALUES
(
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'alice@example.com',
    '$2a$10$e0MYzXyjpJS7Pd0RVvHwHeFx4fQnhdQnZZF9uG6x1Z1ZzR12uLh9e',
    '2025-05-09T12:00:00Z',
    '{"role":"admin","signup_source":"referral"}',
    '2025-05-09T10:00:00Z',
    '2025-05-09T10:00:00Z',
    NULL
),
(
    '3d594650-3436-11e5-bf21-0800200c9a67',
    'bobby@example.com',
    '$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa',
    NULL,
    '{"role":"user","signup_source":"organic"}',
    '2025-05-09T10:05:00Z',
    '2025-05-09T10:05:00Z',
    NULL
),
(
    '6f1e3e3a-1c55-4f19-8341-8132f374dc5f',
    'carol@example.com',
    '$2a$10$wHk8Zkk8s5DdAOpTmLkp8O4fZzPLAlZsYMHcFzU4sdkuXwYlVjOBK',
    '2025-05-09T11:00:00Z',
    '{"role":"moderator","interests":["go","sql"]}',
    '2025-05-09T10:10:00Z',
    '2025-05-09T10:10:00Z',
    '2025-05-09T12:00:00Z'
	);
	`

const (
	mockUserID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	mockEmail  = "alice@example.com"
	fmtErrSeed = "failed to seed users: %v"
)

func TestIntegrationRepository_List(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	row := tx.QueryRow("SELECT COUNT(id) FROM users")
	var numUsers int
	if err = row.Scan(&numUsers); err != nil {
		t.Fatalf("failed to count the users: %v", err)
	}

	if numUsers == 0 {
		t.Fatal("no users were inserted")
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)
	repo := user.NewRepository(conn)

	users, err := repo.List(txCtx)
	if err != nil {
		t.Errorf("repo.ListUsers(txCtx) = %v, want: %v", err, nil)
	}

	gotLen, wantLen := len(users), numUsers
	if gotLen != wantLen {
		t.Errorf("len(users) = %d, want: %d", gotLen, wantLen)
	}
}

func TestIntegrationRepository_Find(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	repo := user.NewRepository(conn)
	verifiedAt := time.Date(2025, time.May, 9, 20, 0, 0, 0, time.Local)
	wantUser := user.User{
		Model: model.Model{
			ID:        mockUserID,
			CreatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
			UpdatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
		},
		Email:      mockEmail,
		VerifiedAt: &verifiedAt,
	}
	gotUser, err := repo.Find(txCtx, mockUserID)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	gotID := gotUser.ID
	wantID := wantUser.ID

	if gotID != wantID {
		t.Errorf("gotUser.ID = %q, want: %q", gotID, wantID)
	}

	gotEmail := gotUser.Email
	wantEmail := wantUser.Email

	if gotEmail != wantEmail {
		t.Errorf("gotUser.Email = %q, want: %q", gotEmail, wantEmail)
	}

	gotVerifiedAt := gotUser.VerifiedAt
	wantVerifiedAt := wantUser.VerifiedAt

	const fmtErrCreate = "gotUser.CreatedAt = %v, want: %v"

	if !gotVerifiedAt.Equal(*wantVerifiedAt) {
		t.Errorf(fmtErrCreate, gotVerifiedAt, wantVerifiedAt)
	}

	gotCreatedAt := gotUser.CreatedAt
	wantCreatedAt := wantUser.CreatedAt

	if !gotCreatedAt.Equal(wantCreatedAt) {
		t.Errorf(fmtErrCreate, gotCreatedAt, wantCreatedAt)
	}

	gotUpdatedAt := gotUser.UpdatedAt
	wantUpdatedAt := wantUser.UpdatedAt

	if !gotUpdatedAt.Equal(wantUpdatedAt) {
		t.Errorf("gotUser.CreatedAt = %v, want: %v", gotUpdatedAt, wantUpdatedAt)
	}
}

func TestIntegrationRepository_FindByEmail(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	repo := user.NewRepository(conn)
	verifiedAt := time.Date(2025, time.May, 9, 20, 0, 0, 0, time.Local)
	wantUser := &user.User{
		Model: model.Model{
			ID:        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			CreatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
			UpdatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
		},
		Email:        mockEmail,
		PasswordHash: "$2a$10$e0MYzXyjpJS7Pd0RVvHwHeFx4fQnhdQnZZF9uG6x1Z1ZzR12uLh9e",
		VerifiedAt:   &verifiedAt,
	}
	u, err := repo.FindByEmail(txCtx, mockEmail)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	if !reflect.DeepEqual(u, wantUser) {
		t.Errorf("repo.FindUserByEmail(txCtx, %q) = %+v, want: %+v", mockEmail, u, wantUser)
	}
}

func TestIntegrationRepository_Create(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	tests := []struct {
		name   string
		params user.CreateUserParams
		err    error
	}{
		{
			name: "User is available",
			params: user.CreateUserParams{
				Email:    "agnis@example.com",
				Password: "hashed",
			},
			err: err,
		},
		{
			name: "User already exists",
			params: user.CreateUserParams{
				Email:    "agnis@example.com",
				Password: "hashed",
			},
			err: db.ErrUniqueConstraintViolation,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			txCtx := db.NewContextWithTx(ctx, tx)

			repo := user.NewRepository(conn)
			u, err := repo.Create(txCtx, tc.params)
			if err != nil {
				if tc.err == nil {
					t.Fatalf("failed to create user: %v", err)
				}

				if err != tc.err {
					t.Errorf("repo.CreateUser(txCtx, tc.params) = %v, want: %v", err, tc.err)
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

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

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
			txCtx := db.NewContextWithTx(ctx, tx)

			userRepo := user.NewRepository(conn)
			err := userRepo.Delete(txCtx, tc.userID)
			if err != nil {
				if tc.err == nil {
					t.Fatalf("failed to delete user: %v", err)
				}

				if err != tc.err {
					t.Errorf("repo.DeleteUser(txCtx, %q) = %v, want: %v", tc.userID, err, tc.err)
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

	conn, tx := db.Setup(t)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	userRepo := user.NewRepository(conn)
	currentTimestamp := time.Now().Truncate(time.Microsecond)
	updates := &user.User{
		VerifiedAt: &currentTimestamp,
	}
	if err := userRepo.Update(txCtx, updates, mockUserID); err != nil {
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
