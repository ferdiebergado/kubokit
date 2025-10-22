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
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const configFile = "../../config.json"

func TestService_RegisterUser(t *testing.T) {
	t.Parallel()

	const user1 = "user1@example.com"

	now := time.Now().Truncate(0)

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, email, password string
		userRepo              user.Repository
		signer                jwt.Signer
		mailer                email.Mailer
		user                  user.User
		err                   error
	}{
		{
			name:     "Successful registration",
			email:    user1,
			password: "test",
			userRepo: &user.StubRepo{
				CreateFunc: func(ctx context.Context, params user.CreateUserParams) (user.User, error) {
					return user.User{
						Model: model.Model{
							ID:        "1",
							CreatedAt: now,
							UpdatedAt: now,
						},
						Email: params.Email,
					}, nil
				},
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return nil, user.ErrNotFound
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
			userRepo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
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
			mailer: &email.StubMailer{},
			signer: &jwt.StubSigner{},
			user:   user.User{},
			err:    auth.ErrExists,
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
				Hasher:   hasher,
				Mailer:   tc.mailer,
				Signer:   tc.signer,
				Txmgr:    &db.StubTxManager{},
				UserRepo: tc.userRepo,
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
			gotUser, err := authSvc.Register(ctx, params)
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

	errTokenExpired := errors.New("token expired")

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)
	if err != nil {
		t.Fatal(err)
	}

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
			mailer := &email.StubMailer{}
			txMgr := &db.StubTxManager{}
			cfg := &config.Config{
				App:   &config.App{},
				JWT:   &config.JWT{},
				Email: &config.Email{},
			}

			repo := &auth.StubRepo{
				VerifyFunc: tc.repoVerifyFunc,
			}

			userRepo := &user.StubRepo{}

			provider := &auth.ServiceProvider{
				CfgApp:   cfg.App,
				CfgJWT:   cfg.JWT,
				CfgEmail: cfg.Email,
				Hasher:   hasher,
				Mailer:   mailer,
				Signer:   signer,
				Txmgr:    txMgr,
				UserRepo: userRepo,
			}
			svc, err := auth.NewService(repo, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			if err := svc.Verify(ctx, tc.token); err != nil {
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
		ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
			return nil
		},
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatal(err)
	}

	hasher, err := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)
	if err != nil {
		t.Fatal(err)
	}

	userRepo := &user.StubRepo{
		FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
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
		UserRepo: userRepo,
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
