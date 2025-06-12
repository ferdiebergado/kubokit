package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"

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
		t.Fatalf("seed users: %v", err)
	}

	tests := []struct {
		name   string
		userID string
		err    error
	}{
		{"User exists", "3d594650-3436-11e5-bf21-0800200c9a66", nil},
		{"User does not exists", "00000000-0000-0000-0000-000000000000", user.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := auth.NewRepository(conn)
			ctx := context.Background()
			if err = repo.VerifyUser(ctx, tt.userID); !errors.Is(err, tt.err) {
				t.Errorf("repo.VerifyUser(ctx, %q) = %v, want: %v", tt.userID, err, tt.err)
			}

			if tt.err == nil {
				var verifiedAt *time.Time
				err = conn.QueryRowContext(ctx, "SELECT verified_at FROM users WHERE id = $1", tt.userID).Scan(&verifiedAt)
				if err != nil {
					t.Fatalf("failed to fetch user: %v", err)
				}
				if verifiedAt == nil {
					t.Errorf("verifiedAt = %v, want: not nil", verifiedAt)
				}
			}
		})
	}
}

func TestIntegrationRepository_ChangeUserPassword(t *testing.T) {
	conn, cleanUp := db.Setup(t)
	defer cleanUp("TRUNCATE users")

	_, err := conn.Exec(queryUserSeed)
	if err != nil {
		t.Fatalf("seed users: %v", err)
	}

	tests := []struct {
		name         string
		passwordHash string
		email        string
		err          error
	}{
		{"User exists", "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa", "bob@example.com", nil},
		{"User does not exists", "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa", "sue@example.com", user.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := auth.NewRepository(conn)
			ctx := context.Background()
			testPassword := "test"
			if err = repo.ChangeUserPassword(ctx, tt.email, testPassword); !errors.Is(err, tt.err) {
				t.Errorf("repo.ChangeUserPassword(ctx, %q, %q) = %v\nwant: %v", tt.email, testPassword, err, tt.err)
			}

			if tt.err == nil {
				var passwordHash string
				err = conn.QueryRowContext(ctx, "SELECT password_hash FROM users WHERE email = $1", tt.email).Scan(&passwordHash)
				if err != nil {
					t.Fatalf("failed to fetch user: %v", err)
				}
				if passwordHash == "" || passwordHash == tt.passwordHash {
					t.Errorf("passwordHash = %q, want: not equal to %q", passwordHash, tt.passwordHash)
				}
			}
		})
	}
}
