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
	mockEmail    = "test@example.com"
	mockPassword = "test"
	mockAppEmail = "app@example.com"
)

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

func TestService_LoginSuccess(t *testing.T) {
	t.Parallel()

	const mockToken = "mock_token"

	now := time.Now()

	hasher := createHasher(t)

	mockPasswordHash, err := hasher.Hash(mockPassword)
	if err != nil {
		t.Fatalf("failed to hash password: %q: %v", mockPassword, err)
	}

	userRepo := &user.StubRepo{
		FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
			return &user.User{
				Model: model.Model{
					ID:        "1",
					CreatedAt: now,
					UpdatedAt: now,
				},
				Email:        mockEmail,
				PasswordHash: mockPasswordHash,
				VerifiedAt:   &now,
			}, nil
		},
	}

	signer := &jwt.StubSigner{
		SignFunc: func(subject string, audience []string, duration time.Duration) (string, error) {
			return mockToken, nil
		},
	}

	deps := &auth.Dependencies{
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		Hasher:   hasher,
		UserRepo: userRepo,
		Signer:   signer,
	}
	svc := auth.NewService(deps)
	params := auth.LoginParams{
		Email:    mockEmail,
		Password: mockPassword,
	}
	session, err := svc.Login(t.Context(), params)
	if err != nil {
		t.Fatalf("svc.Login returned an error: %v", err)
	}

	if session.AccessToken != mockToken {
		t.Errorf("session.AccessToken = %q, want: %q", session.AccessToken, mockToken)
	}

	if session.RefreshToken != mockToken {
		t.Errorf("session.RefreshToken = %q, want: %q", session.RefreshToken, mockToken)
	}

	wantExp := now.Add(mockJWTCfg.TTL.Duration).UnixNano() / int64(time.Millisecond)
	if session.ExpiresIn < wantExp {
		t.Errorf("session.ExpiresIn = %d, want: > %d", session.ExpiresIn, wantExp)
	}

	if session.TokenType != auth.TokenType {
		t.Errorf("session.TokenType = %q, want: %q", session.TokenType, auth.TokenType)
	}

	wantUser := auth.UserInfo{
		ID:    "1",
		Email: mockEmail,
	}

	if !reflect.DeepEqual(*session.User, wantUser) {
		t.Errorf("session.User = %+v, want: %+v", *session.User, wantUser)
	}
}

func TestService_RegisterSuccess(t *testing.T) {
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
			name: "user exists",
			repo: &user.StubRepo{
				FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
					return &mockUser, nil
				},
			},
			wantErr: auth.ErrUserExists,
		},
		{
			name: "repo failure",
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

	now := time.Now()
	verifiedUser := mockUser
	verifiedUser.VerifiedAt = &now

	tests := []struct {
		name     string
		repo     auth.Repository
		userRepo user.Repository
	}{
		{
			name: "user not yet verified",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return nil
				},
			},
			userRepo: &user.StubRepo{
				FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &mockUser, nil
				},
			},
		},
		{
			name: "user already verified",
			userRepo: &user.StubRepo{
				FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &verifiedUser, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			signer := createSigner(t)

			mockDeps := &auth.Dependencies{
				Repo:     tt.repo,
				UserRepo: tt.userRepo,
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
		})
	}
}

func TestService_VerifyFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		repo     auth.Repository
		userRepo user.Repository
		token    string
		wantErr  error
	}{
		{
			name:     "invalid verification token",
			repo:     &auth.StubRepo{},
			userRepo: &user.StubRepo{},
			token:    "mock_token",
			wantErr:  auth.ErrInvalidToken,
		},
		{
			name: "user does not exist",
			repo: &auth.StubRepo{},
			userRepo: &user.StubRepo{
				FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return nil, user.ErrNotFound
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "repo failure",
			repo: &auth.StubRepo{
				VerifyFunc: func(ctx context.Context, userID string) error {
					return errMockRepoFailure
				},
			},
			userRepo: &user.StubRepo{
				FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &mockUser, nil
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
				UserRepo: tt.userRepo,
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

	signer := createSigner(t)

	deps := &auth.Dependencies{
		Repo:     repo,
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   createHasher(t),
		Signer:   signer,
	}

	svc := auth.NewService(deps)

	mockToken, err := signer.Sign(mockUserID, []string{"/auth/reset"}, mockJWTCfg.TTL.Duration)
	if err != nil {
		t.Fatalf("failed to create mock token: %v", err)
	}

	mockParams := auth.ResetPasswordParams{
		Token:    mockToken,
		Password: "test",
	}

	if err := svc.ResetPassword(t.Context(), mockParams); err != nil {
		t.Errorf("svc.ResetPassword(t.Context(), %+v) = %v, want: %v", mockParams, err, nil)
	}
}

func TestService_ResetPasswordFails(t *testing.T) {
	t.Parallel()

	signer := createSigner(t)

	mockToken, err := signer.Sign(mockUserID, []string{"/auth/reset"}, mockJWTCfg.TTL.Duration)
	if err != nil {
		t.Fatalf("failed to create mock token: %v", err)
	}

	tests := []struct {
		name    string
		repo    auth.Repository
		params  auth.ResetPasswordParams
		wantErr error
	}{
		{
			name: "user does not exist",
			repo: &auth.StubRepo{
				ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
					return auth.ErrUserNotFound
				},
			},
			params: auth.ResetPasswordParams{
				Token:    mockToken,
				Password: mockPassword,
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "invalid token",
			params: auth.ResetPasswordParams{
				Token:    "123",
				Password: mockPassword,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "repo failure",
			repo: &auth.StubRepo{
				ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
					return errMockRepoFailure
				},
			},
			params: auth.ResetPasswordParams{
				Token:    mockToken,
				Password: mockPassword,
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
				Signer:   signer,
			}

			svc := auth.NewService(deps)

			err = svc.ResetPassword(t.Context(), tt.params)
			if err == nil {
				t.Fatal("svc.ResetPassword did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.Register(t.Context(), %+v) = %v, want %v", tt.params, err, tt.wantErr)
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
