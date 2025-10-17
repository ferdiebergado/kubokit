//go:build integration

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

func TestIntegrationRepository_Verify(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(queryUserSeed)
	if err != nil {
		t.Fatalf("failed to seed users: %v", err)
	}

	tests := []struct {
		name   string
		userID string
		err    error
	}{
		{"User exists", "3d594650-3436-11e5-bf21-0800200c9a66", nil},
		{"User does not exists", "00000000-0000-0000-0000-000000000000", user.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			txCtx := db.NewContextWithTx(ctx, tx)
			repo := auth.NewRepository(conn)
			err := repo.Verify(txCtx, tc.userID)
			if !errors.Is(err, tc.err) {
				t.Errorf("repo.Verify(txCtx, %q) = %v, want: %v", tc.userID, err, tc.err)
			}

			if tc.err == nil {
				const query = "SELECT verified_at, updated_at FROM users WHERE id = $1"
				row := tx.QueryRowContext(ctx, query, tc.userID)
				var verifiedAt *time.Time
				var updatedAt time.Time
				if err := row.Scan(&verifiedAt, &updatedAt); err != nil {
					t.Fatalf("failed to fetch verified user: %v", err)
				}

				if verifiedAt.IsZero() {
					t.Errorf("verifiedAt = %v, want: non-zero", verifiedAt)
				}

				if !updatedAt.Truncate(0).Equal(verifiedAt.Truncate(0)) {
					t.Errorf("updatedAt = %v, want: %v", updatedAt, verifiedAt)
				}
			}
		})
	}
}

func TestIntegrationRepository_ChangePassword(t *testing.T) {
	t.Parallel()

	conn, tx := db.Setup(t)

	_, err := tx.Exec(queryUserSeed)
	if err != nil {
		t.Fatalf("failed to seed users: %v", err)
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			txCtx := db.NewContextWithTx(ctx, tx)

			var initialUpdatedAt time.Time

			if tc.err == nil {
				const query = "SELECT updated_at FROM users WHERE email = $1"
				row := tx.QueryRowContext(ctx, query, tc.email)
				if err := row.Scan(&initialUpdatedAt); err != nil {
					t.Fatalf("failed to fetch current user: %v", err)
				}
			}

			repo := auth.NewRepository(conn)
			const testPassword = "test"
			if err = repo.ChangePassword(txCtx, tc.email, testPassword); !errors.Is(err, tc.err) {
				t.Errorf("repo.ChangePassword(txCtx, %q, %q) = %v, want: %v", tc.email, testPassword, err, tc.err)
			}

			if tc.err == nil {
				const query = "SELECT password_hash, updated_at FROM users WHERE email = $1"
				var passwordHash string
				var updatedAt time.Time

				row := tx.QueryRowContext(ctx, query, tc.email)
				if err := row.Scan(&passwordHash, &updatedAt); err != nil {
					t.Fatalf("failed to fetch updated user: %v", err)
				}
				if passwordHash == "" || passwordHash == tc.passwordHash {
					t.Errorf("passwordHash = %q, want: not equal to %q", passwordHash, tc.passwordHash)
				}

				if updatedAt.Before(initialUpdatedAt) || updatedAt.Equal(initialUpdatedAt) {
					t.Errorf("updatedAt = %v, want: after %v", updatedAt, initialUpdatedAt)
				}
			}
		})
	}
}
