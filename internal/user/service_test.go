package user_test

import (
	"context"
	"testing"
	"time"

	"github.com/ferdiebergado/slim/internal/db"
	"github.com/ferdiebergado/slim/internal/user"
)

type stubRepo struct {
	GetAllUsersFunc func(ctx context.Context) ([]user.User, error)
}

func (m *stubRepo) GetAllUsers(ctx context.Context) ([]user.User, error) {
	return m.GetAllUsersFunc(ctx)
}

func TestService_GetAllUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now()
	users := []user.User{
		{
			Model: db.Model{
				ID:        "1",
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "123@test.com",
			PasswordHash: "hash1",
			VerifiedAt:   &now,
		},
	}
	repo := &stubRepo{
		GetAllUsersFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}
	service := user.NewService(repo)
	allUsers, err := service.GetAllUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}

	wantLen := len(users)
	gotLen := len(allUsers)
	if gotLen != wantLen {
		t.Errorf("want: %d, got: %d users", wantLen, gotLen)
	}
}
