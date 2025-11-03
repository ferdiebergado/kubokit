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

const (
	mockUserID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
	mockEmail  = "alice@example.com"
	fmtErrSeed = "failed to seed users: %v"
)

func TestIntegrationRepository_List(t *testing.T) {
	t.Parallel()

	tx := setup(t)
	repo := user.NewRepository(tx)

	users, err := repo.List(t.Context())
	if err != nil {
		t.Fatalf("failed to list users: %v", err)
	}

	gotLen, wantLen := len(users), 3
	if gotLen != wantLen {
		t.Errorf("len(users) = %d, want: %d", gotLen, wantLen)
	}
}

func setup(t *testing.T) *sql.Tx {
	t.Helper()

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
	);`

	_, tx := db.Setup(t)
	_, err := tx.Exec(querySeedUsers)
	if err != nil {
		t.Fatalf(fmtErrSeed, err)
	}

	return tx
}

func TestIntegrationRepository_FindReturnsUser(t *testing.T) {
	t.Parallel()

	tx := setup(t)
	repo := user.NewRepository(tx)

	u, err := repo.Find(t.Context(), mockUserID)
	if err != nil {
		t.Fatalf("failed to find user with id: %q: %v", mockUserID, err)
	}

	const (
		createdAt  = "2025-05-09T10:00:00Z"
		verifiedAt = "2025-05-09T12:00:00Z"
	)

	wantCreatedAt := parseTime(t, createdAt)
	wantUpdatedAt := parseTime(t, createdAt)
	wantVerifiedAt := parseTime(t, verifiedAt)

	wantUser := &user.User{
		Model: model.Model{
			ID:        mockUserID,
			CreatedAt: wantCreatedAt,
			UpdatedAt: wantUpdatedAt,
		},
		Email:      mockEmail,
		VerifiedAt: &wantVerifiedAt,
	}

	u.Model.CreatedAt = u.Model.CreatedAt.In(time.UTC)
	u.Model.UpdatedAt = u.Model.UpdatedAt.In(time.UTC)

	if u.VerifiedAt != nil {
		t := u.VerifiedAt.In(time.UTC).Truncate(time.Microsecond)
		u.VerifiedAt = &t
	}

	if !reflect.DeepEqual(u, wantUser) {
		t.Errorf("repo.Find(ctx, %q) = %+v, want: %+v", mockUserID, u, wantUser)
	}
}

func parseTime(t *testing.T, timeStr string) time.Time {
	t.Helper()

	val, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		t.Fatalf("failed to parse time string: %q: %v", timeStr, err)
	}

	return val
}

func TestIntegrationRepository_FindByEmail(t *testing.T) {
	t.Parallel()

	tx := setup(t)

	ctx := context.Background()

	repo := user.NewRepository(tx)
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
	u, err := repo.FindByEmail(ctx, mockEmail)
	if err != nil {
		t.Fatalf("failed to find user: %v", err)
	}

	if !reflect.DeepEqual(u, wantUser) {
		t.Errorf("repo.FindUserByEmail(txCtx, %q) = %+v, want: %+v", mockEmail, u, wantUser)
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
			tx := setup(t)
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
			tx := setup(t)
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
	tx := setup(t)

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
