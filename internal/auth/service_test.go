package auth_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
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
	if h.HashFunc == nil {
		return "", errors.New("Hash is not implemented by stub")
	}
	return h.HashFunc(plain)
}

func (h stubHasher) Verify(plain, hash string) (bool, error) {
	panic("not implemented") // TODO: Implement
}

type stubMailer struct {
	SendHTMLFunc func(to []string, subject string, tmplName string, data map[string]string) error
}

func (m *stubMailer) SendPlain(to []string, subject string, body string) error {
	panic("not implemented") // TODO: Implement
}

func (m *stubMailer) SendHTML(to []string, subject string, tmplName string, data map[string]string) error {
	if m.SendHTMLFunc == nil {
		return errors.New("SendHTML not implemented by stub")
	}
	return m.SendHTMLFunc(to, subject, tmplName, data)
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
	t.Parallel()

	now := time.Now().Truncate(0)
	var tests = []struct {
		name       string
		testUser   user.User
		createFunc func(ctx context.Context, params user.CreateUserParams) (user.User, error)
	}{
		{"Successful registration",
			user.User{
				Model: db.Model{
					ID:        "1",
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email: "abc@example.com",
			},
			func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
				return user.User{
					Model: db.Model{
						ID:        "1",
						CreatedAt: now,
						UpdatedAt: now,
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

			hasher := &stubHasher{
				HashFunc: func(_ string) (string, error) {
					return "hashed", nil
				},
			}

			mailer := &stubMailer{
				SendHTMLFunc: func(to []string, subject, tmplName string, data map[string]string) error {
					return nil
				},
			}

			providers := &auth.Providers{
				Hasher: hasher,
				Mailer: mailer,
			}

			cfg := &config.Config{
				Server: &config.Server{
					URL:  "localhost:8888",
					Port: 8888,
				},
				Email: &config.Email{
					Templates: "../../web/templates",
					Layout:    "layout.html",
					Sender:    "test@example.com",
					VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
				},
			}

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

			wantUser, gotUser := tt.testUser, newUser
			if !reflect.DeepEqual(gotUser, wantUser) {
				t.Errorf("newUser = %+v\nwant: %+v", gotUser, wantUser)
			}
		})
	}
}
