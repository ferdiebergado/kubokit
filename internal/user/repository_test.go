//go:build integration

package user_test

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"os"
	"testing"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/slim/internal/db"
	"github.com/ferdiebergado/slim/internal/user"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const sqlUsers = `
INSERT INTO users (id, email, password_hash, verified_at, metadata, created_at, updated_at, deleted_at)
VALUES (
    'f47ac10b-58cc-4372-a567-0e02b2c3d479',
    'alice@example.com',
    '$2a$10$e0MYzXyjpJS7Pd0RVvHwHeFx4fQnhdQnZZF9uG6x1Z1ZzR12uLh9e', -- bcrypt hash
    '2025-05-09T12:00:00Z',
    '{"role":"admin","signup_source":"referral"}',
    '2025-05-09T10:00:00Z',
    '2025-05-09T10:00:00Z',
    NULL
);

INSERT INTO users (id, email, password_hash, verified_at, metadata, created_at, updated_at, deleted_at)
VALUES (
    '3d594650-3436-11e5-bf21-0800200c9a66',
    'bob@example.com',
    '$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa',
    NULL,
    '{"role":"user","signup_source":"organic"}',
    '2025-05-09T10:05:00Z',
    '2025-05-09T10:05:00Z',
    NULL
);

INSERT INTO users (id, email, password_hash, verified_at, metadata, created_at, updated_at, deleted_at)
VALUES (
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

var conn *sql.DB

func TestMain(m *testing.M) {
	if err := env.Load("../../.env.testing"); err != nil {
		log.Fatal(err)
	}

	var err error
	conn, err = db.Connect(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func seedUsers(t *testing.T) {
	t.Helper()
	_, err := conn.Exec(sqlUsers)
	if err != nil {
		t.Fatal(err)
	}
}

func resetDB() {
	_, err := conn.Exec("TRUNCATE users")
	if err != nil {
		slog.Error("reset db failed", "reason", err)
	}
}

func TestRepository_GetAllUsers(t *testing.T) {
	t.Parallel()
	seedUsers(t)

	ctx := context.Background()
	repo := user.NewRepository(conn)

	users, err := repo.GetAllUsers(ctx)
	if err != nil {
		t.Errorf("repo.GetAllUsers() = %v, want %v", err, nil)
	}

	userLen := len(users)
	wantLen := 3

	if userLen != wantLen {
		t.Errorf("len(users) = %v, want %v", userLen, wantLen)
	}

	t.Cleanup(resetDB)
}
