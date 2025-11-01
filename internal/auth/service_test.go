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

const mockAppEmail = "app@example.com"

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

	mockSMTPCfg = &config.SMTP{
		Host:     "localhost",
		Port:     1025,
		User:     mockAppEmail,
		Password: "mock_email_password",
	}
)

func TestService_Register(t *testing.T) {
	t.Parallel()

	const (
		mockEmail    = "test@example.com"
		mockPassword = "test"
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
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: mockEmailCfg,
				Hasher:   createHasher(t),
				Mailer:   createMailer(t),
				Signer:   createSigner(t),
				UserRepo: tc.repo,
			}

			svc := auth.NewService(&auth.StubRepo{}, mockProvider)

			mockParams := auth.RegisterParams{
				Email:    mockEmail,
				Password: mockPassword,
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

			signer := createSigner(t)

			mockProvider := &auth.ServiceProvider{
				CfgApp:   mockAppCfg,
				CfgEmail: mockEmailCfg,
				CfgJWT:   mockJWTCfg,
				Signer:   signer,
			}

			svc := auth.NewService(tc.repo, mockProvider)

			var err error
			mockToken := tc.token
			if mockToken == "" {
				mockToken, err = signer.Sign("user1", []string{"/verify"}, mockJWTCfg.TTL.Duration)
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
				Hasher:   createHasher(t),
			}

			svc := auth.NewService(tc.repo, provider)

			mockParams := auth.ResetPasswordParams{
				UserID:   "1",
				Password: "test",
			}

			err := svc.ResetPassword(context.Background(), mockParams)
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

	return security.NewArgon2Hasher(mockArgon2Cfg, "paminta")
}

func createMailer(t *testing.T) *email.SMTPMailer {
	t.Helper()

	mailer, err := email.NewSMTPMailer(mockSMTPCfg, mockEmailCfg)
	if err != nil {
		t.Fatalf("failed to create mailer: %v", err)
	}

	return mailer
}

func createSigner(t *testing.T) *jwt.GolangJWTSigner {
	t.Helper()

	return jwt.NewGolangJWTSigner(mockJWTCfg, mockAppCfg.Key)
}
