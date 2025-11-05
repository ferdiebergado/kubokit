//go:build integration

package user_test

import (
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
	mockUserID   = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	mockEmail    = "alice@example.com"
	mockPassword = "test"
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

func TestIntegrationRepository_CreateSuccess(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := user.NewRepository(tx)

	mockParams := user.CreateParams{
		Email:        mockEmail,
		PasswordHash: mockPassword,
	}
	u, err := repo.Create(t.Context(), mockParams)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	if u.Email != mockEmail {
		t.Errorf("u.Email = %q, want: %q", u.Email, mockEmail)
	}

	if u.PasswordHash != mockPassword {
		t.Errorf("u.Password = %q, want: %q", u.PasswordHash, mockPassword)
	}

	if u.VerifiedAt != nil {
		t.Errorf("u.verifiedAt = %v, want: %v", u.VerifiedAt, nil)
	}

	if u.CreatedAt.IsZero() {
		t.Errorf("u.CreatedAt = %v, want: non-zero time", u.CreatedAt)
	}

	if u.UpdatedAt.IsZero() {
		t.Errorf("u.UpdatedAt = %v, want: non-zero time", u.UpdatedAt)
	}
}

func TestIntegrationRepository_CreateUserExistsFails(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)

	mockParams := user.CreateParams{
		Email:        mockUsers[0].Email,
		PasswordHash: mockPassword,
	}
	_, err := repo.Create(t.Context(), mockParams)
	if err == nil {
		t.Fatal("repo.Create did not return an error")
	}

	wantErr := user.ErrDuplicate
	if !errors.Is(err, wantErr) {
		t.Errorf("repo.Create(t.Context(), %q) = %v, want: %v", mockParams, err, wantErr)
	}
}

func TestIntegrationRepository_DeleteSuccess(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)
	ctx := t.Context()
	mockUserID := mockUsers[0].ID

	if err := repo.Delete(ctx, mockUserID); err != nil {
		t.Fatalf("failed to delete user: %v", err)
	}

	const query = "SELECT id FROM users WHERE id = $1"
	row := tx.QueryRowContext(ctx, query, mockUserID)
	var id string
	if err := row.Scan(&id); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("user was not deleted: id: %q: %v", id, err)
	}
}

func TestIntegrationRepository_DeleteUserDontExistFails(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := user.NewRepository(tx)
	ctx := t.Context()

	err := repo.Delete(ctx, mockUserID)
	if err == nil {
		t.Fatal("repo.Delete did not return an error")
	}

	wantErr := user.ErrNotFound
	if !errors.Is(err, wantErr) {
		t.Errorf("repo.Delete(ctx, %q) = %v, want: %v", mockEmail, err, wantErr)
	}
}

func TestIntegrationRepository_UpdateSuccess(t *testing.T) {
	t.Parallel()

	mockUsers, tx := setup(t)
	repo := user.NewRepository(tx)
	ctx := t.Context()

	mockUser := mockUsers[0]
	mockUserID := mockUser.ID
	mockUpdates := &user.User{
		PasswordHash: "new_mock_hash",
	}
	if err := repo.Update(ctx, mockUpdates, mockUserID); err != nil {
		t.Fatalf("failed to update user: %v", err)
	}

	const query = "SELECT password_hash, updated_at FROM users WHERE id = $1"

	row := tx.QueryRowContext(ctx, query, mockUserID)

	var (
		passwordHash string
		updatedAt    time.Time
	)
	if err := row.Scan(&passwordHash, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("no user with id: %q: %v", mockUserID, err)
		}
		t.Fatalf("query failed: %v", err)
	}

	if passwordHash != mockUpdates.PasswordHash {
		t.Errorf("passwordHash = %q, want: %q", passwordHash, updatedAt)
	}

	if !updatedAt.After(mockUser.UpdatedAt) {
		t.Errorf("updatedAt = %v, want: after %v", updatedAt, mockUser.UpdatedAt)
	}
}

func TestIntegrationRepository_UpdateUserDontExistFails(t *testing.T) {
	t.Parallel()

	_, tx := setup(t)
	repo := user.NewRepository(tx)
	ctx := t.Context()

	mockUpdates := &user.User{
		PasswordHash: "new_mock_hash",
	}
	err := repo.Update(ctx, mockUpdates, mockUserID)
	if err == nil {
		t.Fatal("repo.Update did not return an error")
	}

	wantErr := user.ErrNotFound
	if !errors.Is(err, wantErr) {
		t.Errorf("repo.Update(ctx, %v, %q) = %v, want: %v", mockUpdates, mockUserID, err, wantErr)
	}
}
