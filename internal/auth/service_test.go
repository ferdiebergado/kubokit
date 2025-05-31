package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type stubAuthRepo struct {
	RegisterUserFunc func(ctx context.Context, params auth.RegisterUserParams) (user.User, error)
}

func (r *stubAuthRepo) RegisterUser(ctx context.Context, params auth.RegisterUserParams) (user.User, error) {
	if r.RegisterUserFunc == nil {
		return user.User{}, errors.New("RegisterUser not implemented in stub")
	}
	return r.RegisterUserFunc(ctx, params)
}

func (r *stubAuthRepo) LoginUser(ctx context.Context, params auth.LoginUserParams) (accessToken string, refreshToken string, err error) {
	panic("not implemented") // TODO: Implement
}

func (r *stubAuthRepo) VerifyUser(ctx context.Context, userID string) error {
	panic("not implemented") // TODO: Implement
}

func (r *stubAuthRepo) ChangeUserPassword(ctx context.Context, email string, newPassword string) error {
	panic("not implemented") // TODO: Implement
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

type stubUserSvc struct {
	CreateUserFunc      func(ctx context.Context, params user.CreateUserParams) (user.User, error)
	FindUserByEmailFunc func(ctx context.Context, email string) (user.User, error)
}

func (s *stubUserSvc) CreateUser(ctx context.Context, params user.CreateUserParams) (user.User, error) {
	if s.CreateUserFunc == nil {
		return user.User{}, errors.New("CreateUser not implemented in stub")
	}

	return s.CreateUserFunc(ctx, params)
}

func (s *stubUserSvc) ListUsers(ctx context.Context) ([]user.User, error) {
	panic("not implemented") // TODO: Implement
}

func (s *stubUserSvc) FindUserByEmail(ctx context.Context, email string) (user.User, error) {
	if s.FindUserByEmailFunc == nil {
		return user.User{}, errors.New("FindUserByEmail not implemented in stub")
	}
	return s.FindUserByEmailFunc(ctx, email)
}

func TestService_RegisterUser(t *testing.T) {
	var tests = []struct {
		name       string
		testUser   user.User
		createFunc func(ctx context.Context, params user.CreateUserParams) (user.User, error)
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
			func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
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
			authRepo := &stubAuthRepo{}
			userSvc := &stubUserSvc{
				CreateUserFunc: tt.createFunc,
				FindUserByEmailFunc: func(ctx context.Context, email string) (user.User, error) {
					return user.User{}, nil
				},
			}

			providers := &auth.Providers{
				Hasher: stubHasher{},
			}
			cfg := &config.Config{}

			authSvc := auth.NewService(authRepo, userSvc, providers, cfg)
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
