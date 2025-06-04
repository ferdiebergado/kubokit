package user_test

import (
	"context"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_ListUsers(t *testing.T) {
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
	repo := &user.StubRepo{
		ListUsersFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}
	service := user.NewService(repo)
	allUsers, err := service.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}

	wantLen, gotLen := len(users), len(allUsers)
	if gotLen != wantLen {
		t.Errorf("len(allUsers) = %d\nwant: %d", wantLen, gotLen)
	}
}
