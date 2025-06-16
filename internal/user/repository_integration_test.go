package user_test

import (
	"context"
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

func TestIntegrationRepository_GetAllUsers(t *testing.T) {
	t.Parallel()

	conn, tx, cleanUp := db.Setup(t)
	t.Cleanup(cleanUp)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	row := tx.QueryRow("SELECT COUNT(*) FROM users")
	var numUsers int
	if err = row.Scan(&numUsers); err != nil {
		t.Fatal(err)
	}

	if numUsers == 0 {
		t.Fatal("no users were inserted")
	}

	repo := user.NewRepository(conn)

	users, err := repo.ListUsers(txCtx)
	if err != nil {
		t.Errorf("repo.ListUsers(txCtx) = %v, want: %v", err, nil)
	}

	gotLen, wantLen := len(users), numUsers
	if gotLen != wantLen {
		t.Errorf("len(users) = %d, want: %d", gotLen, wantLen)
	}
}

func TestIntegrationRepository_FindUser(t *testing.T) {
	t.Parallel()

	conn, tx, cleanUp := db.Setup(t)
	t.Cleanup(cleanUp)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	repo := user.NewRepository(conn)
	const userID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	verifiedAt := time.Date(2025, time.May, 9, 20, 0, 0, 0, time.Local)
	wantUser := user.User{
		Model: model.Model{
			ID:        userID,
			CreatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
			UpdatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
		},
		Email:      "alice@example.com",
		VerifiedAt: &verifiedAt,
	}
	u, err := repo.FindUser(txCtx, userID)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	if !reflect.DeepEqual(u, wantUser) {
		t.Errorf("repo.FindUser(txCtx, %q) = %+v, want: %+v", userID, u, wantUser)
	}
}

func TestIntegrationRepository_FindUserByEmail(t *testing.T) {
	t.Parallel()

	conn, tx, cleanUp := db.Setup(t)
	t.Cleanup(cleanUp)

	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	txCtx := db.NewContextWithTx(ctx, tx)

	repo := user.NewRepository(conn)
	const testEmail = "alice@example.com"
	verifiedAt := time.Date(2025, time.May, 9, 20, 0, 0, 0, time.Local)
	wantUser := &user.User{
		Model: model.Model{
			ID:        "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			CreatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
			UpdatedAt: time.Date(2025, time.May, 9, 18, 0, 0, 0, time.Local),
		},
		Email:        "alice@example.com",
		PasswordHash: "$2a$10$e0MYzXyjpJS7Pd0RVvHwHeFx4fQnhdQnZZF9uG6x1Z1ZzR12uLh9e",
		VerifiedAt:   &verifiedAt,
	}
	u, err := repo.FindUserByEmail(txCtx, testEmail)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	if !reflect.DeepEqual(u, wantUser) {
		t.Errorf("repo.FindUserByEmail(txCtx, %q) = %+v, want: %+v", testEmail, u, wantUser)
	}
}
