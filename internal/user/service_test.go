package user_test

import (
	"context"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_List(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	users := []user.User{
		{
			Model: model.Model{
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
		ListFunc: func(_ context.Context) ([]user.User, error) {
			return users, nil
		},
	}
	hasher := &hash.StubHasher{
		HashFunc: func(_ string) (string, error) {
			return "hashed", nil
		},
	}
	service := user.NewService(repo, hasher)
	allUsers, err := service.List(ctx)
	if err != nil {
		t.Fatal(err)
	}

	wantLen, gotLen := len(users), len(allUsers)
	if gotLen != wantLen {
		t.Errorf("len(allUsers) = %d, want: %d", wantLen, gotLen)
	}
}
