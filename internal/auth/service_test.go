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
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	configFile = "../../config.json"
	user1      = "user1@example.com"
)

func TestService_Register(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(0)

	cfg := &config.Config{
		App: &config.App{
			URL: "localhost:8888",
			Key: "123",
		},
		Server: &config.Server{
			Port: 8888,
		},
		Argon2: &config.Argon2{
			Memory:     1024,
			Iterations: 1,
			Threads:    1,
			SaltLength: 8,
			KeyLength:  8,
		},
		SMTP: &config.SMTP{
			Host:     "",
			Port:     0,
			User:     user1,
			Password: "",
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

	hasher, err := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)
	if err != nil {
		t.Fatal(err)
	}

	mailer, err := email.NewSMTPMailer(cfg.SMTP, cfg.Email)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, email, password string
		userRepo              user.Repository
		signer                auth.Signer
		user                  user.User
		err                   error
	}{
		{
			name:     "Successful registration",
			email:    user1,
			password: "test",
			userRepo: &user.StubRepo{
				CreateFunc: func(ctx context.Context, params user.CreateParams) (user.User, error) {
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

			signer: &auth.StubSigner{
				SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
					return "1", nil
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
			signer: &auth.StubSigner{},
			user:   user.User{},
			err:    user.ErrDuplicate,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &auth.ServiceProvider{
				CfgApp:   cfg.App,
				CfgJWT:   cfg.JWT,
				CfgEmail: cfg.Email,
				Hasher:   hasher,
				Mailer:   mailer,
				Signer:   tc.signer,
				Txmgr:    &db.StubTxManager{},
				UserRepo: tc.userRepo,
			}
			authSvc, err := auth.NewService(&auth.StubRepo{}, provider)
			if err != nil {
				t.Fatal(err)
			}

			ctx := context.Background()
			params := auth.RegisterParams{
				Email:    tc.email,
				Password: tc.password,
			}
			gotUser, err := authSvc.Register(ctx, params)
			if err != nil {
				if tc.err == nil {
					t.Fatal(err)
				}

				if !errors.Is(err, tc.err) {
					t.Errorf("authSvc.Register(ctx, params) = %v, want: %v", err, tc.err)
				}
			}

			if !reflect.DeepEqual(gotUser, tc.user) {
				t.Errorf("authSvc.Register(ctx, params) = %+v, want: %+v", gotUser, tc.user)
			}
		})
	}
}

func TestService_Verify(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name    string
		repo    auth.Repository
		token   string
		wantErr error
	}

	testCases := []testCase{
		{
			name: "valid verification token",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return nil
				},
			},
		},
		{
			name:    "invalid verification token",
			repo:    &auth.StubRepo{},
			token:   "mock_token",
			wantErr: errors.New("token is malformed"),
		},
		{
			name: "user does not exists",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return user.ErrNotFound
				},
			},
			wantErr: user.ErrNotFound,
		},
		{
			name: "repo failure",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return errors.New("query failed")
				},
			},
			wantErr: &auth.ServiceError{Op: "verify user", Err: errors.New("query failed")},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockConfig := &config.Config{
				App: &config.App{Key: "123"},
				JWT: &config.JWT{
					JTILength:  8,
					Issuer:     "localhost",
					TTL:        timex.Duration{Duration: 5 * time.Minute},
					RefreshTTL: timex.Duration{Duration: 10 * time.Minute},
				},
				Email: &config.Email{},
			}

			signer, err := jwt.NewGolangJWTSigner(mockConfig.JWT, mockConfig.App.Key)
			if err != nil {
				t.Fatalf("failed to create signer: %v", err)
			}

			mockProvider := &auth.ServiceProvider{
				CfgApp:   mockConfig.App,
				CfgEmail: mockConfig.Email,
				CfgJWT:   mockConfig.JWT,
				Signer:   signer,
			}

			svc, err := auth.NewService(tc.repo, mockProvider)
			if err != nil {
				t.Fatalf("failed to create auth service: %v", err)
			}

			mockToken := tc.token
			if mockToken == "" {
				mockToken, err = signer.Sign("user1", []string{"/verify"}, mockConfig.JWT.TTL.Duration)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
			}

			err = svc.Verify(context.Background(), mockToken)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("service did not return an error")
				}

				var wantSvcErr *auth.ServiceError
				if errors.As(tc.wantErr, &wantSvcErr) {
					var svcErr *auth.ServiceError
					if !errors.As(err, &svcErr) {
						t.Fatal("service did not return a ServiceError")
					}

					if svcErr.Op != wantSvcErr.Op {
						t.Errorf("svcErr.Op = %q, want: %q", svcErr.Op, wantSvcErr.Op)
					}
					if svcErr.Error() != wantSvcErr.Error() {
						t.Errorf("svcErr.Error() = %q, want: %q", svcErr.Error(), wantSvcErr.Error())
					}
				}
			}
		})
	}
}

func TestService_ResetPassword(t *testing.T) {
	t.Parallel()

	// TODO: replace with mock config
	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Failed to load config file: %v", err)
	}

	hasher, err := security.NewArgon2Hasher(cfg.Argon2, cfg.Key)
	if err != nil {
		t.Fatalf("Failed to create hasher: %v", err)
	}

	type testCase struct {
		name           string
		changePassword func(ctx context.Context, email, newPassword string) error
		find           func(ctx context.Context, userID string) (*user.User, error)
		wantErr        error
	}

	testcases := []testCase{
		{
			name: "user exists",
			changePassword: func(ctx context.Context, email string, newPassword string) error {
				return nil
			},
			find: func(ctx context.Context, userID string) (*user.User, error) {
				return &user.User{}, nil
			},
		},
		{
			name: "user does not exists",
			changePassword: func(ctx context.Context, email string, newPassword string) error {
				return nil
			},
			find: func(ctx context.Context, userID string) (*user.User, error) {
				return nil, user.ErrNotFound
			},
			wantErr: user.ErrNotFound,
		},
		{
			name: "db error",
			changePassword: func(ctx context.Context, email string, newPassword string) error {
				return errors.New("query failed")
			},
			find: func(ctx context.Context, userID string) (*user.User, error) {
				return &user.User{}, nil
			},
			wantErr: &auth.ServiceError{Op: "change password", Err: errors.New("query failed")},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			repo := &auth.StubRepo{ChangePasswordFunc: tc.changePassword}
			userRepo := &user.StubRepo{FindUserFunc: tc.find}

			provider := &auth.ServiceProvider{
				CfgApp:   cfg.App,
				CfgJWT:   cfg.JWT,
				CfgEmail: cfg.Email,
				Hasher:   hasher,
				UserRepo: userRepo,
			}

			svc, err := auth.NewService(repo, provider)
			if err != nil {
				t.Fatalf("Failed to create auth service: %v", err)
			}

			params := auth.ResetPasswordParams{
				UserID:   "1",
				Password: "abc@123",
			}
			err = svc.ResetPassword(context.Background(), params)

			var wantSvcErr *auth.ServiceError
			if errors.As(tc.wantErr, &wantSvcErr) {
				var svcErr *auth.ServiceError
				if !errors.As(err, &svcErr) {
					t.Fatalf("err is not a ServiceError")
				}

				if svcErr.Op != wantSvcErr.Op {
					t.Errorf("svc.ResetPassword(context.Background(),params) = %+s, want: %s", svcErr.Op, wantSvcErr.Op)
				}

				if svcErr.Error() != wantSvcErr.Error() {
					t.Errorf("svc.ResetPassword(context.Background(),params) = %+v, want: %+v", svcErr.Error(), wantSvcErr.Error())
				}
				return
			}

			if !errors.Is(err, tc.wantErr) {
				t.Errorf("svc.ResetPassword(context.Background(),params) = %+v, want: %+v", err, tc.wantErr)
			}
		})
	}
}
