package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type stubRepo struct {
	ListUsersFunc func(ctx context.Context) ([]user.User, error)
}

func (r *stubRepo) CreateUser(ctx context.Context, params user.CreateUserParams) (user.User, error) {
	panic("not implemented") // TODO: Implement
}

func (r *stubRepo) ListUsers(ctx context.Context) ([]user.User, error) {
	if r.ListUsersFunc == nil {
		return nil, errors.New("ListUsers not implemented by stub")
	}
	return r.ListUsersFunc(ctx)
}

func (r *stubRepo) FindUserByEmail(ctx context.Context, email string) (user.User, error) {
	panic("not implemented") // TODO: Implement
}

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
	repo := &stubRepo{
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
		t.Errorf("\nwant: %d\n got: %d users", wantLen, gotLen)
	}
}
