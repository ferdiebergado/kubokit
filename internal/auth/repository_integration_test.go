//go:build integration

package auth_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/platform/db"

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

	tests := []struct {
		name, userID string
		wantErr      error
	}{
		{
			name:   "user exists returns no error",
			userID: "3d594650-3436-11e5-bf21-0800200c9a66",
		},
		{
			name:    "user does not exist returns error",
			userID:  "3d594650-3436-11e5-bf21-0800200c9a67",
			wantErr: auth.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tx := setup(t)
			repo := auth.NewRepository(tx)
			err := repo.Verify(context.Background(), tt.userID)
			if err != nil {
				if tt.wantErr == nil {
					t.Fatal("auth repo should not return an error")
				}

				if !errors.Is(err, tt.wantErr) {
					t.Errorf("repo.Verify(context.Background(), %q) = %v, want %v", tt.userID, err, tt.wantErr)
				}

				return
			}

			if tt.wantErr != nil {
				t.Fatal("auth repo did not return an error")
			}

			const query = "SELECT verified_at, updated_at FROM users WHERE id = $1"
			row := tx.QueryRowContext(context.Background(), query, tt.userID)

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
		})
	}

}

func setup(t *testing.T) *sql.Tx {
	t.Helper()

	_, tx := db.Setup(t)

	_, err := tx.Exec(queryUserSeed)
	if err != nil {
		t.Fatalf("failed to seed users: %v", err)
	}

	return tx
}

func TestIntegrationRepository_ChangePassword(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		passwordHash string
		userID       string
		wantErr      error
	}{
		{
			name:         "User exists",
			passwordHash: "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa",
			userID:       "3d594650-3436-11e5-bf21-0800200c9a66",
		},
		{
			name:         "User does not exists",
			passwordHash: "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z1Z3MxE8lmyy6h6Zy/YPj4Oa",
			userID:       "3d594650-3436-11e5-bf21-0800200c9a67",
			wantErr:      auth.ErrUserNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			tx := setup(t)

			var initialUpdatedAt time.Time

			if tt.wantErr == nil {
				const query = "SELECT updated_at FROM users WHERE id = $1"
				row := tx.QueryRowContext(ctx, query, tt.userID)
				if err := row.Scan(&initialUpdatedAt); err != nil {
					t.Fatalf("failed to fetch current user: %v", err)
				}
			}

			repo := auth.NewRepository(tx)
			const testPassword = "test"
			if err := repo.ChangePassword(ctx, tt.userID, testPassword); !errors.Is(err, tt.wantErr) {
				t.Errorf("repo.ChangePassword(txCtx, %q, %q) = %v, want: %v", tt.userID, testPassword, err, tt.wantErr)
			}

			if tt.wantErr == nil {
				const query = "SELECT password_hash, updated_at FROM users WHERE id = $1"
				var passwordHash string
				var updatedAt time.Time

				row := tx.QueryRowContext(ctx, query, tt.userID)
				if err := row.Scan(&passwordHash, &updatedAt); err != nil {
					t.Fatalf("failed to fetch updated user: %v", err)
				}
				if passwordHash == "" || passwordHash == tt.passwordHash {
					t.Errorf("passwordHash = %q, want: not equal to %q", passwordHash, tt.passwordHash)
				}

				if updatedAt.Before(initialUpdatedAt) || updatedAt.Equal(initialUpdatedAt) {
					t.Errorf("updatedAt = %v, want: after %v", updatedAt, initialUpdatedAt)
				}
			}
		})
	}
}
