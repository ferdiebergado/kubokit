package user_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/model"
	"github.com/ferdiebergado/kubokit/internal/user"
)

var (
	now = time.Now()

	mockUsers = []user.User{
		{
			Model: model.Model{
				ID:        "1",
				Metadata:  []byte(`{"role":"admin"}`),
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "user1@example.com",
			PasswordHash: "hashed123",
			VerifiedAt:   &now,
		},
		{
			Model: model.Model{
				ID:        "2",
				Metadata:  []byte(`{"role":"user"}`),
				CreatedAt: now,
				UpdatedAt: now,
			},
			Email:        "user2@example.com",
			PasswordHash: "hashed456",
		},
	}
)

func TestService_ListSuccess(t *testing.T) {
	t.Parallel()

	repo := &user.StubRepo{
		ListFunc: func(_ context.Context) ([]user.User, error) {
			return mockUsers, nil
		},
	}

	svc := user.NewService(repo)

	users, err := svc.List(t.Context())
	if err != nil {
		t.Fatalf("svc.List should not return an error: %v", err)
	}

	if !reflect.DeepEqual(users, mockUsers) {
		t.Errorf("svc.List(t.Context()) = %+v, want: %+v", users, mockUsers)
	}
}

func TestService_ListFails(t *testing.T) {
	t.Parallel()

	errMockRepoFailure := errors.New("query failed")

	repo := &user.StubRepo{
		ListFunc: func(_ context.Context) ([]user.User, error) {
			return nil, errMockRepoFailure
		},
	}

	svc := user.NewService(repo)

	_, err := svc.List(t.Context())
	if err == nil {
		t.Fatal("svc.List did not return an error")
	}

	if !errors.Is(err, errMockRepoFailure) {
		t.Errorf("svc.List(t.Context()) = %+v, want: %+v", err, errMockRepoFailure)
	}
}
