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

func TestService_List(t *testing.T) {
	t.Parallel()

	errMockRepoFailure := errors.New("query failed")

	now := time.Now()

	mockUsers := []user.User{
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
			VerifiedAt:   nil,
		},
	}

	tests := []struct {
		name      string
		repo      user.Repository
		wantUsers []user.User
		wantErr   error
	}{
		{
			name: "success returns users",
			repo: &user.StubRepo{
				ListFunc: func(_ context.Context) ([]user.User, error) {
					return mockUsers, nil
				},
			},
			wantUsers: mockUsers,
		},
		{
			name: "repo failure returns error",
			repo: &user.StubRepo{
				ListFunc: func(_ context.Context) ([]user.User, error) {
					return nil, errMockRepoFailure
				},
			},
			wantErr: errMockRepoFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := user.NewService(tt.repo)

			users, err := svc.List(context.Background())

			if (err != nil) != (tt.wantErr != nil) {
				t.Fatalf("service.List(ctx) = %v, wantErr: %v", err, tt.wantErr)
			}

			if err != nil && tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("service.List(ctx) = %v, wantErr: %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(users, tt.wantUsers) {
				t.Errorf("service.List(ctx) = %+v, want: %+v", users, tt.wantUsers)
			}
		})
	}
}
