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

var (
	errMockRepoFailure = errors.New("query failed")

	now = time.Now().Truncate(0)

	mockUser = user.User{
		Model: model.Model{
			ID:        "1",
			Metadata:  []byte{},
			CreatedAt: now,
			UpdatedAt: now,
		},
		Email:        mockEmail,
		PasswordHash: "mock_hashed",
	}

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

func TestService_RegisterShouldReturnNewUser(t *testing.T) {
	t.Parallel()

	userRepo := &user.StubRepo{
		FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
			return nil, user.ErrNotFound
		},
		CreateFunc: func(ctx context.Context, params user.CreateParams) (user.User, error) {
			return mockUser, nil
		},
	}

	mockDeps := &auth.Dependencies{
		Repo:     &auth.StubRepo{},
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   createHasher(t),
		Mailer:   createMailer(t),
		Signer:   createSigner(t),
		UserRepo: userRepo,
	}

	svc := auth.NewService(mockDeps)

	mockParams := auth.RegisterParams{
		Email:    mockEmail,
		Password: mockPassword,
	}

	u, err := svc.Register(t.Context(), mockParams)
	if err != nil {
		t.Fatalf("svc.Register should not return an error: %v", err)
	}

	if !reflect.DeepEqual(u, mockUser) {
		t.Errorf("svc.Register(t.Context(), %+v) = %+v, want %+v", mockParams, u, mockUser)
	}
}

func TestService_RegisterFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    user.Repository
		wantErr error
	}{
		{
			name: "user exists returns error",
			repo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return &mockUser, nil
				},
			},
			wantErr: auth.ErrUserExists,
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
			wantErr: errMockRepoFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockDeps := &auth.Dependencies{
				Repo:     &auth.StubRepo{},
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: mockEmailCfg,
				Hasher:   createHasher(t),
				Mailer:   createMailer(t),
				Signer:   createSigner(t),
				UserRepo: tt.repo,
			}

			svc := auth.NewService(mockDeps)

			mockParams := auth.RegisterParams{
				Email:    mockEmail,
				Password: mockPassword,
			}

			_, err := svc.Register(context.Background(), mockParams)
			if err == nil {
				t.Fatal("auth service should return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.Register(context.Background(), params) = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_VerifySuccess(t *testing.T) {
	t.Parallel()

	repo := &auth.StubRepo{
		VerifyFunc: func(ctx context.Context, userID string) error {
			return nil
		},
	}

	signer := createSigner(t)

	mockDeps := &auth.Dependencies{
		Repo:     repo,
		CfgApp:   mockAppCfg,
		CfgEmail: mockEmailCfg,
		CfgJWT:   mockJWTCfg,
		Signer:   signer,
	}

	svc := auth.NewService(mockDeps)

	mockToken, err := signer.Sign(mockUserID, []string{"/verify"}, mockJWTCfg.TTL.Duration)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	if err := svc.Verify(t.Context(), mockToken); err != nil {
		t.Errorf("svc.Verify(t.Context(), mockToken) = %v, want: %v", err, nil)
	}
}

func TestService_VerifyFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    auth.Repository
		token   string
		wantErr error
	}{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer := createSigner(t)

			mockDeps := &auth.Dependencies{
				Repo:     tt.repo,
				CfgApp:   mockAppCfg,
				CfgEmail: mockEmailCfg,
				CfgJWT:   mockJWTCfg,
				Signer:   signer,
			}

			svc := auth.NewService(mockDeps)

			var err error
			mockToken := tt.token
			if mockToken == "" {
				mockToken, err = signer.Sign(mockUserID, []string{"/verify"}, mockJWTCfg.TTL.Duration)
				if err != nil {
					t.Fatalf("failed to sign token: %v", err)
				}
			}

			err = svc.Verify(t.Context(), mockToken)
			if err == nil {
				t.Fatal("svc.Verify did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.Verify(t.Context(), mockToken) = %v, want: %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_ResetPasswordSuccess(t *testing.T) {
	t.Parallel()

	repo := &auth.StubRepo{
		ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
			return nil
		},
	}

	deps := &auth.Dependencies{
		Repo:     repo,
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   createHasher(t),
	}

	svc := auth.NewService(deps)

	mockParams := auth.ResetPasswordParams{
		UserID:   mockUserID,
		Password: "test",
	}

	if err := svc.ResetPassword(t.Context(), mockParams); err != nil {
		t.Errorf("svc.ResetPassword(t.Context(), %+v) = %v, want: %v", mockParams, err, nil)
	}
}

func TestService_ResetPasswordFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		repo    auth.Repository
		wantErr error
	}{
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			deps := &auth.Dependencies{
				Repo:     tt.repo,
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: mockEmailCfg,
				Hasher:   createHasher(t),
			}

			svc := auth.NewService(deps)

			mockParams := auth.ResetPasswordParams{
				UserID:   mockUserID,
				Password: mockPassword,
			}

			err := svc.ResetPassword(t.Context(), mockParams)
			if err == nil {
				t.Fatal("svc.ResetPassword did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.Register(t.Context(), %+v) = %v, want %v", mockParams, err, tt.wantErr)
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

func createSigner(t *testing.T) jwt.Signer {
	t.Helper()

	return jwt.NewGolangJWTSigner(mockJWTCfg, mockAppCfg.Key)
}
