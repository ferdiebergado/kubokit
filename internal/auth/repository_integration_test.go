package auth_test

import (
	"context"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/db"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const queryUserSeed = `
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
);`

func TestIntegrationRepository_VerifyUser(t *testing.T) {
	conn, cleanUp := db.Setup(t)
	defer cleanUp("TRUNCATE users")

	_, err := conn.Exec(queryUserSeed)
	if err != nil {
		t.Fatal(err)
	}

	repo := auth.NewRepository(conn)
	userID := "3d594650-3436-11e5-bf21-0800200c9a66"
	if err := repo.VerifyUser(context.Background(), userID); err != nil {
		t.Errorf("\ngot: %v\nwant: nil", err)
	}
}

func TestIntegrationRepository_ChangeUserPassword(t *testing.T) {
	conn, cleanUp := db.Setup(t)
	defer cleanUp("TRUNCATE users")

	_, err := conn.Exec(queryUserSeed)
	if err != nil {
		t.Fatal(err)
	}

	repo := auth.NewRepository(conn)
	testEmail := "bob@example.com"
	testPassword := "test"
	if err := repo.ChangeUserPassword(context.Background(), testEmail, testPassword); err != nil {
		t.Errorf("\ngot: %v\nwant: nil", err)
	}
}
