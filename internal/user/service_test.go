package user_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_ListUsers(t *testing.T) {
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

func TestService_CreateUser(t *testing.T) {
	testID := "1"
	testEmail := "test@example.com"
	testPass := "hashed"
	now := time.Now().Truncate(0)
	repo := user.StubRepo{
		CreateUserFunc: func(_ context.Context, params user.CreateUserParams) (user.User, error) {
			return user.User{
				Model: model.Model{
					ID:        testID,
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email:        params.Email,
				PasswordHash: params.PasswordHash,
			}, nil
		},
	}
	svc := user.NewService(&repo)
	params := user.CreateUserParams{
		Email:        testEmail,
		PasswordHash: testPass,
	}
	ctx := context.Background()
	gotUser, err := svc.CreateUser(ctx, params)
	if err != nil {
		t.Fatal(err)
	}

	wantUser := user.User{
		Model: model.Model{
			ID:        testID,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Email:        testEmail,
		PasswordHash: testPass,
	}
	if !reflect.DeepEqual(gotUser, wantUser) {
		t.Errorf("svc.CreateUser(ctx, params) = %+v \nwant: %+v", gotUser, wantUser)
	}
}
