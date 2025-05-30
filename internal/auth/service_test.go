package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type stubAuthRepo struct {
	CreateUserFunc func(ctx context.Context, params auth.CreateUserParams) (user.User, error)
}

func (r stubAuthRepo) CreateUser(ctx context.Context, params auth.CreateUserParams) (user.User, error) {
	if r.CreateUserFunc != nil {
		return r.CreateUserFunc(ctx, params)
	}
	return user.User{}, nil
}

func (r stubAuthRepo) ChangeUserPassword(ctx context.Context, email, newPassword string) error {
	return nil
}

func (r stubAuthRepo) FindUserByEmail(ctx context.Context, email string) (user.User, error) {
	return user.User{}, nil
}

func (r stubAuthRepo) ListUsers(ctx context.Context) ([]user.User, error) {
	return nil, nil
}

func (r stubAuthRepo) VerifyUser(ctx context.Context, email string) error {
	return nil
}

type stubHasher struct {
	HashFunc func(plain string) (string, error)
}

func (h stubHasher) Hash(plain string) (string, error) {
	if h.HashFunc != nil {
		return h.HashFunc(plain)
	}
	return "", nil
}

func (h stubHasher) Verify(plain, hash string) (bool, error) {
	return false, nil
}

func TestService_RegisterUser(t *testing.T) {
	var tests = []struct {
		name       string
		testUser   user.User
		createFunc func(ctx context.Context, params auth.CreateUserParams) (user.User, error)
	}{
		{"Successful registration",
			user.User{
				Model: db.Model{
					ID:        "1",
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Email: "abc@example.com",
			},
			func(ctx context.Context, params auth.CreateUserParams) (user.User, error) {
				return user.User{
					Model: db.Model{
						ID:        "1",
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
					Email: "abc@example.com",
				}, nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authRepo := stubAuthRepo{}

			if tt.createFunc != nil {
				authRepo.CreateUserFunc = tt.createFunc
			}

			providers := &auth.Providers{
				Hasher: stubHasher{},
			}
			cfg := &config.Config{}
			authSvc := auth.NewService(authRepo, providers, cfg)
			ctx := context.Background()
			params := auth.RegisterUserParams{
				Email:    "abc@example.com",
				Password: "test",
			}
			newUser, err := authSvc.RegisterUser(ctx, params)
			if err != nil {
				t.Fatal(err)
			}

			wantEmail, gotEmail := tt.testUser.Email, newUser.Email
			if gotEmail != wantEmail {
				t.Errorf("newUser = %v, want %v", gotEmail, wantEmail)
			}
		})
	}

}
