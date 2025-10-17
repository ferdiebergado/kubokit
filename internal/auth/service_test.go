package auth_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/model"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

func TestService_RegisterUser(t *testing.T) {
	t.Parallel()

	const user1 = "user1@example.com"

	now := time.Now().Truncate(0)

	tests := []struct {
		name, email, password string
		userSvc               user.UserService
		hasher                hash.Hasher
		signer                jwt.Signer
		mailer                email.Mailer
		user                  user.User
		err                   error
	}{
		{
			name:     "Successful registration",
			email:    user1,
			password: "test",
			userSvc: &user.StubService{
				CreateUserFunc: func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
					return user.User{
						Model: model.Model{
							ID:        "1",
							CreatedAt: now,
							UpdatedAt: now,
						},
						Email: params.Email,
					}, nil
				},
				FindUserByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return nil, user.ErrNotFound
				},
			},
			hasher: &hash.StubHasher{
				HashFunc: func(plain string) (string, error) {
					return "hashed", nil
				},
			},
			signer: &jwt.StubSigner{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "1", nil
				},
			},
			mailer: &email.StubMailer{
				SendHTMLFunc: func(to []string, subject, tmplName string, data map[string]string) error {
					return nil
				},
			},
			user: user.User{
				Model: model.Model{
					ID:        "1",
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email: user1,
			},
		},
		{
			name:     "User already exists",
			email:    user1,
			password: "test",
			userSvc: &user.StubService{
				FindUserByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return &user.User{
						Model: model.Model{
							ID:        "1",
							CreatedAt: now,
							UpdatedAt: now,
						},
						Email: user1,
					}, nil
				},
			},
			hasher: &hash.StubHasher{},
			mailer: &email.StubMailer{},
			signer: &jwt.StubSigner{},
			user:   user.User{},
			err:    auth.ErrUserExists,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{
				App: &config.App{
					URL: "localhost:8888",
				},
				Server: &config.Server{
					Port: 8888,
				},
				Email: &config.Email{
					Templates: "../../web/templates",
					Layout:    "layout.html",
					Sender:    "test@example.com",
					VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
				},
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "localhost:8888",
					TTL:        timex.Duration{Duration: 15 * time.Minute},
					RefreshTTL: timex.Duration{Duration: 24 * time.Hour},
				},
			}

			provider := &auth.ServiceProvider{
				CfgApp:   cfg.App,
				CfgJWT:   cfg.JWT,
				CfgEmail: cfg.Email,
				Hasher:   tc.hasher,
				Mailer:   tc.mailer,
				Signer:   tc.signer,
				Txmgr:    &db.StubTxManager{},
				UsrSvc:   tc.userSvc,
			}
			authSvc, err := auth.NewService(&auth.StubRepo{}, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			params := auth.RegisterUserParams{
				Email:    tc.email,
				Password: tc.password,
			}
			gotUser, err := authSvc.RegisterUser(ctx, params)
			if err != nil {
				if tc.err == nil {
					t.Fatal(err)
				}

				if !errors.Is(err, tc.err) {
					t.Errorf("authSvc.RegisterUser(ctx, params) = %v, want: %v", err, tc.err)
				}
			}

			if !reflect.DeepEqual(gotUser, tc.user) {
				t.Errorf("authSvc.RegisterUser(ctx, params) = %+v, want: %+v", gotUser, tc.user)
			}
		})
	}
}

func TestVerifyUser(t *testing.T) {
	t.Parallel()

	var errTokenExpired = errors.New("token expired")

	type TestCase struct {
		name             string
		repoVerifyFunc   func(ctx context.Context, userID string) error
		signerVerifyFunc func(tokenString string) (*jwt.Claims, error)
		token            string
		err              error
	}

	tests := []TestCase{
		{
			name: "Token is valid",
			repoVerifyFunc: func(ctx context.Context, userID string) error {
				return nil
			},
			signerVerifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return &jwt.Claims{UserID: "1"}, nil
			},
			token: "verification_token",
		},
		{
			name: "Token has expired",
			repoVerifyFunc: func(ctx context.Context, userID string) error {
				return nil
			},
			signerVerifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return nil, errTokenExpired
			},
			token: "verification_token",
			err:   errTokenExpired,
		},
		{
			name: "Query error",
			repoVerifyFunc: func(ctx context.Context, userID string) error {
				return db.ErrQueryFailed
			},
			signerVerifyFunc: func(tokenString string) (*jwt.Claims, error) {
				return &jwt.Claims{UserID: "1"}, nil
			},
			token: "verification_token",
			err:   db.ErrQueryFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signer := &jwt.StubSigner{
				VerifyFunc: tc.signerVerifyFunc,
			}
			hasher := &hash.StubHasher{}
			mailer := &email.StubMailer{}
			txMgr := &db.StubTxManager{}
			cfg := &config.Config{
				App:   &config.App{},
				JWT:   &config.JWT{},
				Email: &config.Email{},
			}

			repo := &auth.StubRepo{
				VerifyUserFunc: tc.repoVerifyFunc,
			}

			usrSvc := &user.StubService{}

			provider := &auth.ServiceProvider{
				CfgApp:   cfg.App,
				CfgJWT:   cfg.JWT,
				CfgEmail: cfg.Email,
				Hasher:   hasher,
				Mailer:   mailer,
				Signer:   signer,
				Txmgr:    txMgr,
				UsrSvc:   usrSvc,
			}
			svc, err := auth.NewService(repo, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if err := svc.VerifyUser(ctx, tc.token); err != nil {
				if tc.err == nil {
					t.Fatal(err)
				}

				if !errors.Is(err, tc.err) {
					t.Errorf("svc.VerifyUser(ctx, %q) = %v, want: %v", tc.token, err, tc.err)
				}
			}
		})
	}
}

func TestService_ResetPassword(t *testing.T) {
	repo := &auth.StubRepo{
		ChangeUserPasswordFunc: func(ctx context.Context, email, newPassword string) error {
			return nil
		},
	}

	hasher := &hash.StubHasher{
		HashFunc: func(plain string) (string, error) {
			return "hashed", nil
		},
	}

	svcUsr := &user.StubService{
		FindUserByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
			return &user.User{}, nil
		},
	}
	provider := &auth.ServiceProvider{
		CfgApp:   &config.App{},
		CfgJWT:   &config.JWT{},
		CfgEmail: &config.Email{},
		Hasher:   hasher,
		Mailer:   nil,
		Signer:   nil,
		Txmgr:    nil,
		UsrSvc:   svcUsr,
	}
	svc, err := auth.NewService(repo, provider)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	params := auth.ResetPasswordParams{
		Email:    "abc@example.com",
		Password: "abc@123",
	}
	if err := svc.ResetPassword(context.Background(), params); err != nil {
		t.Errorf("svc.ResetPassword(context.Background(),params) = %v, want: nil", err)
	}
}
