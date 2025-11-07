//go:build integration

package auth_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/user"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestIntegrationRepository_VerifySuccess(t *testing.T) {
	t.Parallel()

	mockUser, tx := setup(t)
	repo := auth.NewRepository(tx)
	ctx := t.Context()

	mockUserID := mockUser.ID

	if err := repo.Verify(ctx, mockUserID); err != nil {
		t.Errorf("repo.Verify(ctx, %q) = %v, want: %v", mockUserID, err, nil)
	}

	const query = "SELECT verified_at, updated_at FROM users WHERE id = $1"
	row := tx.QueryRowContext(ctx, query, mockUserID)

	var (
		verifiedAt *time.Time
		updatedAt  time.Time
	)
	if err := row.Scan(&verifiedAt, &updatedAt); err != nil {
		t.Fatalf("failed to retrieve updated columns: %v", err)
	}

	if verifiedAt == nil {
		t.Errorf("verifiedAt = %v, want: %v", verifiedAt, updatedAt)
	}
}

func TestIntegrationRepository_VerifyUserNotFound(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := auth.NewRepository(tx)
	const mockUserID = "3d594650-3436-11e5-bf21-0800200c9a67"
	err := repo.Verify(t.Context(), mockUserID)
	if err == nil {
		t.Fatal("repo.Verify did not return an error")
	}

	wantErr := auth.ErrUserNotFound
	if !errors.Is(err, wantErr) {
		t.Errorf("repo.Verify(t.Context(), %q) = %v, want: %v", mockUserID, err, wantErr)
	}
}

func TestIntegrationRepository_ChangePasswordSuccess(t *testing.T) {
	t.Parallel()

	mockUser, tx := setup(t)
	repo := auth.NewRepository(tx)
	ctx := t.Context()

	const wantPasswordHash = "mock_hashed"
	mockUserID := mockUser.ID
	if err := repo.ChangePassword(ctx, mockUserID, wantPasswordHash); err != nil {
		t.Errorf("repo.ChangePassword(ctx, %q, %q) = %v, want: %v", mockUserID, wantPasswordHash, err, nil)
	}

	const query = "SELECT password_hash FROM users WHERE id = $1"
	row := tx.QueryRowContext(ctx, query, mockUserID)

	var passwordHash string
	if err := row.Scan(&passwordHash); err != nil {
		t.Fatalf("failed to retrieve updated user: %v", err)
	}

	if passwordHash != wantPasswordHash {
		t.Errorf("passwordHash = %q, want: %q", passwordHash, wantPasswordHash)
	}
}

func TestIntegrationRepository_ChangePasswordUserNotFound(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := auth.NewRepository(tx)

	const (
		mockUserID       = "3d594650-3436-11e5-bf21-0800200c9a67"
		mockPasswordHash = "mock_hashed"
	)

	err := repo.ChangePassword(t.Context(), mockUserID, mockPasswordHash)
	if err == nil {
		t.Fatal("repo.ChangePassword did not return an error")
	}

	wantErr := auth.ErrUserNotFound
	if !errors.Is(err, wantErr) {
		t.Errorf("repo.ChangePassword(t.Context(), %q, %q) = %v, want: %v", mockUserID, mockPasswordHash, err, wantErr)
	}
}

func setup(t *testing.T) (user.User, *sql.Tx) {
	t.Helper()

	_, tx := db.Setup(t)

	const query = `
	INSERT INTO users (email, password_hash)
	VALUES ($1, $2)
	RETURNING id, email, password_hash, verified_at, created_at, updated_at`

	row := tx.QueryRowContext(t.Context(), query, mockEmail, mockPassword)

	var mockUser user.User
	if err := row.Scan(&mockUser.ID, &mockUser.Email, &mockUser.PasswordHash, &mockUser.VerifiedAt, &mockUser.CreatedAt, &mockUser.UpdatedAt); err != nil {
		t.Fatalf("failed to retrieve mock user: %v", err)
	}

	return mockUser, tx
}
