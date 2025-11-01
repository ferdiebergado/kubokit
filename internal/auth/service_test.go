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
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	mockAppEmail = "app@example.com"
)

var errMockRepoFailure = errors.New("query failed")

var (
	mockAppCfg = &config.App{Key: "123"}

	mockArgon2Cfg = &config.Argon2{
		Memory:     64,
		Iterations: 1,
		Threads:    1,
		SaltLength: 8,
		KeyLength:  8,
	}

	mockEmailCfg = &config.Email{
		Templates: "../../web/templates",
		Layout:    "layout.html",
		Sender:    mockAppEmail,
		VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
	}

	mockJWTCfg = &config.JWT{
		JTILength:  8,
		Issuer:     mockAppEmail,
		TTL:        timex.Duration{Duration: 5 * time.Minute},
		RefreshTTL: timex.Duration{Duration: 10 * time.Minute},
	}
)

func TestService_Register(t *testing.T) {
	t.Parallel()

	const (
		mockEmail    = "test@example.com"
		mockPassword = "test"
		mockAppEmail = "app@example.com"
	)

	now := time.Now().Truncate(0)

	mockUser := user.User{
		Model: model.Model{
			ID:        "1",
			Metadata:  []byte{},
			CreatedAt: now,
			UpdatedAt: now,
		},
		Email:        mockEmail,
		PasswordHash: "mock_hashed",
	}

	mockConfig := &config.Config{
		Argon2: &config.Argon2{
			Memory:     64,
			Iterations: 1,
			Threads:    1,
			SaltLength: 8,
			KeyLength:  8,
		},
		SMTP: &config.SMTP{
			Host:     "localhost",
			Port:     1025,
			User:     mockAppEmail,
			Password: "mock_email_password",
		},
		Email: &config.Email{
			Templates: "../../web/templates",
			Layout:    "layout.html",
			Sender:    mockAppEmail,
			VerifyTTL: timex.Duration{Duration: 5 * time.Minute},
		},
		JWT: &config.JWT{
			JTILength:  8,
			Issuer:     mockAppEmail,
			TTL:        timex.Duration{Duration: 5 * time.Minute},
			RefreshTTL: timex.Duration{Duration: 10 * time.Minute},
		},
		App: &config.App{Key: "123"},
	}

	hasher, err := security.NewArgon2Hasher(mockConfig.Argon2, "paminta")
	if err != nil {
		t.Fatalf("failed to create hasher: %v", err)
	}

	mailer, err := email.NewSMTPMailer(mockConfig.SMTP, mockConfig.Email)
	if err != nil {
		t.Fatalf("failed to create mailer: %v", err)
	}

	signer, err := jwt.NewGolangJWTSigner(mockConfig.JWT, mockConfig.App.Key)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	mockParams := auth.RegisterParams{
		Email:    mockEmail,
		Password: mockPassword,
	}

	type testCase struct {
		name     string
		repo     user.Repository
		wantUser user.User
		wantErr  error
	}

	testCases := []testCase{
		{
			name: "user does not exist returns new user",
			repo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return nil, user.ErrNotFound
				},
				CreateFunc: func(ctx context.Context, params user.CreateParams) (user.User, error) {
					return mockUser, nil
				},
			},
			wantUser: mockUser,
		},
		{
			name: "user exists returns error",
			repo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return &mockUser, nil
				},
			},
			wantUser: user.User{},
			wantErr:  auth.ErrUserExists,
		},
		{
			name: "repo failure returns error",
			repo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return nil, user.ErrNotFound
				},
				CreateFunc: func(ctx context.Context, params user.CreateParams) (user.User, error) {
					return user.User{}, errMockRepoFailure
				},
			},
			wantUser: user.User{},
			wantErr:  errMockRepoFailure,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mockProvider := &auth.ServiceProvider{
				CfgApp:   mockConfig.App,
				CfgJWT:   mockConfig.JWT,
				CfgEmail: mockConfig.Email,
				Hasher:   hasher,
				Mailer:   mailer,
				Signer:   signer,
				UserRepo: tc.repo,
			}

			svc, err := auth.NewService(&auth.StubRepo{}, mockProvider)
			if err != nil {
				t.Fatalf("failed to create auth service")
			}

			u, err := svc.Register(context.Background(), mockParams)
			if err != nil {
				if tc.wantErr == nil {
					t.Fatal("auth service should not return an error")
				}

				if !errors.Is(err, tc.wantErr) {
					t.Errorf("svc.Register(context.Background(), params) = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if tc.wantErr != nil {
				t.Fatal("auth service should return an error")
			}

			if !reflect.DeepEqual(u, tc.wantUser) {
				t.Errorf("svc.Register(context.Background(), params) = %v, want %v", u, tc.wantUser)
			}
		})
	}
}

func TestService_Verify(t *testing.T) {
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

	type testCase struct {
		name    string
		repo    auth.Repository
		token   string
		wantErr error
	}

	testCases := []testCase{
		{
			name: "valid verification token returns no error",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return nil
				},
			},
		},
		{
			name:    "invalid verification token returns error",
			repo:    &auth.StubRepo{},
			token:   "mock_token",
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "user does not exist returns error",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return auth.ErrUserNotFound
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "repo failure returns error",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return errMockRepoFailure
				},
			},
			wantErr: errMockRepoFailure,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("svc.Verify(context.Background(), mockToken) = %v, want: %v", err, tc.wantErr)
			}
		})
	}
}

func TestService_ResetPassword(t *testing.T) {
	t.Parallel()

	hasher := createHasher(t)

	mockParams := auth.ResetPasswordParams{
		UserID:   "1",
		Password: "test",
	}

	type testCase struct {
		name    string
		repo    auth.Repository
		wantErr error
	}

	testCases := []testCase{
		{
			name: "user exists returns no error",
			repo: &auth.StubRepo{
				ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
					return nil
				},
			},
		},
		{
			name: "user does not exist returns error",
			repo: &auth.StubRepo{
				ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
					return auth.ErrUserNotFound
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "repo failure returns error",
			repo: &auth.StubRepo{
				ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
					return errMockRepoFailure
				},
			},
			wantErr: errMockRepoFailure,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &auth.ServiceProvider{
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: mockEmailCfg,
				Hasher:   hasher,
			}

			svc, err := auth.NewService(tc.repo, provider)
			if err != nil {
				t.Fatalf("failed to create auth service: %v", err)
			}

			err = svc.ResetPassword(context.Background(), mockParams)
			if err != nil {
				if tc.wantErr == nil {
					t.Fatal("auth service should not return an error")
				}

				if !errors.Is(err, tc.wantErr) {
					t.Errorf("svc.Register(context.Background(), params) = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if tc.wantErr != nil {
				t.Errorf("svc.Register(context.Background(), params) = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func createHasher(t *testing.T) *security.Argon2Hasher {
	t.Helper()

	hasher, err := security.NewArgon2Hasher(mockArgon2Cfg, "paminta")
	if err != nil {
		t.Fatalf("failed to create hasher: %v", err)
	}

	return hasher
}
