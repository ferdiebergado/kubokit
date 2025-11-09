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
	timex "github.com/ferdiebergado/kubokit/internal/pkg/time"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
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

func TestService_ChangePasswordSuccess(t *testing.T) {
	t.Parallel()

	userRepo := &user.StubRepo{
		FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
			return &mockUser, nil
		},
	}

	hasher := &auth.StubHasher{
		VerifyFunc: func(plain, hashed string) (bool, error) {
			return true, nil
		},
		HashFunc: func(plain string) (string, error) {
			return "hashed", nil
		},
	}

	repo := &auth.StubRepo{
		ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
			return nil
		},
	}

	deps := &auth.Dependencies{
		Repo:     repo,
		CfgApp:   mockAppCfg,
		CfgJWT:   &config.JWT{},
		CfgEmail: &config.Email{},
		Hasher:   hasher,
		Mailer:   &email.SMTPMailer{},
		Signer:   nil,
		Txmgr:    &db.TxManager{},
		UserRepo: userRepo,
	}
	svc := auth.NewService(deps)
	params := auth.ChangePasswordParams{}
	if err := svc.ChangePassword(t.Context(), params); err != nil {
		t.Errorf("svc.ChangePassword(t.Context(), params) = %v, want: %v", err, nil)
	}
}

func TestService_ChangePasswordFails(t *testing.T) {
	t.Parallel()

	errReadData := errors.New("unable to read random data")
	errQueryFailed := errors.New("query failed")

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "user not found",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer:   nil,
				Txmgr:    &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "incorrect password",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					VerifyFunc: func(plain, hashed string) (bool, error) {
						return false, nil
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
					},
				},
			},
			wantErr: auth.ErrIncorrectPassword,
		},
		{
			name: "hashing error",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					VerifyFunc: func(plain, hashed string) (bool, error) {
						return true, nil
					},
					HashFunc: func(plain string) (string, error) {
						return "", errReadData
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
					},
				},
			},
			wantErr: errReadData,
		},
		{
			name: "repo failure",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return errQueryFailed
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					VerifyFunc: func(plain, hashed string) (bool, error) {
						return true, nil
					},
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
					},
				},
			},
			wantErr: errQueryFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := auth.NewService(tt.deps)
			params := auth.ChangePasswordParams{}
			err := svc.ChangePassword(t.Context(), params)
			if err == nil {
				t.Fatal("svc.ChangePassword did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.ChangePassword(t.Context(),params) = %v, want: %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_LoginSuccess(t *testing.T) {
	t.Parallel()

	const mockToken = "mock_token"

	verifiedUser := mockUser
	verifiedUser.VerifiedAt = &now

	hasher := &auth.StubHasher{
		VerifyFunc: func(plain, hashed string) (bool, error) {
			return true, nil
		},
	}

	userRepo := &user.StubRepo{
		FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
			return &verifiedUser, nil
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
		Repo:     nil,
		CfgEmail: &config.Email{},
		Mailer:   &email.SMTPMailer{},
		Txmgr:    &db.TxManager{},
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

func TestService_LoginFails(t *testing.T) {
	t.Parallel()

	verifiedUser := mockUser
	verifiedUser.VerifiedAt = &now

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "user not found",
			deps: &auth.Dependencies{
				CfgApp: mockAppCfg,
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
				},
				Repo:     nil,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer:   nil,
				Txmgr:    &db.TxManager{},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "user not verified",
			deps: &auth.Dependencies{
				CfgApp: mockAppCfg,
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return &mockUser, nil
					},
				},
				Repo:     nil,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer:   nil,
				Txmgr:    &db.TxManager{},
			},
			wantErr: auth.ErrNotVerified,
		},
		{
			name: "incorrect password",
			deps: &auth.Dependencies{
				CfgApp: mockAppCfg,
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return &verifiedUser, nil
					},
				},
				Hasher: &auth.StubHasher{
					VerifyFunc: func(plain, hashed string) (bool, error) {
						return false, nil
					},
				},
				Repo:     nil,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Mailer:   &email.SMTPMailer{},
				Signer:   nil,
				Txmgr:    &db.TxManager{},
			},
			wantErr: auth.ErrIncorrectPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := auth.NewService(tt.deps)
			params := auth.LoginParams{
				Email:    mockEmail,
				Password: mockPassword,
			}
			_, err := svc.Login(t.Context(), params)
			if err == nil {
				t.Fatal("svc.Login did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.Login(t.Context(), params) = %v, want: %v", err, tt.wantErr)
			}
		})
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

	hasher := &auth.StubHasher{
		HashFunc: func(plain string) (string, error) {
			return "hashed", nil
		},
	}

	mockDeps := &auth.Dependencies{
		Repo:     &auth.StubRepo{},
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   hasher,
		Mailer:   createMailer(t),
		Signer:   createSigner(t),
		UserRepo: userRepo,
		Txmgr:    &db.TxManager{},
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

	errRandomRead := errors.New("unable to read random data")

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "user exists",
			deps: &auth.Dependencies{
				CfgApp:   &config.App{},
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return &mockUser, nil
					},
				},
				Repo: nil,
			},
			wantErr: auth.ErrUserExists,
		},
		{
			name: "hashing error",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "", errRandomRead
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
				},
			},
			wantErr: errRandomRead,
		},
		{
			name: "repo failure",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer: &email.SMTPMailer{},
				Signer: nil,
				Txmgr:  &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindByEmailFunc: func(ctx context.Context, email string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
					CreateFunc: func(ctx context.Context, params user.CreateParams) (user.User, error) {
						return user.User{}, errMockRepoFailure
					},
				},
			},
			wantErr: errMockRepoFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := auth.NewService(tt.deps)

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
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Txmgr:    &db.TxManager{},
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
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Txmgr:    &db.TxManager{},
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

	hasher := &auth.StubHasher{
		HashFunc: func(plain string) (string, error) {
			return "hashed", nil
		},
	}

	signer := createSigner(t)

	deps := &auth.Dependencies{
		Repo:     repo,
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   hasher,
		Signer:   signer,
		Mailer:   &email.SMTPMailer{},
		Txmgr:    &db.TxManager{},
		UserRepo: nil,
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
		deps    *auth.Dependencies
		params  auth.ResetPasswordParams
		wantErr error
	}{
		{
			name: "user does not exist",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return auth.ErrUserNotFound
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer:   &email.SMTPMailer{},
				Signer:   signer,
				Txmgr:    &db.TxManager{},
				UserRepo: nil,
			},
			params: auth.ResetPasswordParams{
				Token:    mockToken,
				Password: mockPassword,
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "invalid token",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return nil
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer:   &email.SMTPMailer{},
				Signer:   signer,
				Txmgr:    &db.TxManager{},
				UserRepo: nil,
			},
			params: auth.ResetPasswordParams{
				Token:    "invalid_token",
				Password: mockPassword,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "repo failure",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return errMockRepoFailure
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   mockJWTCfg,
				CfgEmail: &config.Email{},
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return "hashed", nil
					},
				},
				Mailer:   &email.SMTPMailer{},
				Signer:   signer,
				Txmgr:    &db.TxManager{},
				UserRepo: nil,
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

			svc := auth.NewService(tt.deps)
			err = svc.ResetPassword(t.Context(), tt.params)
			if err == nil {
				t.Fatal("svc.ResetPassword did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.ResetPassword(t.Context(), %+v) = %v, want %v", tt.params, err, tt.wantErr)
			}
		})
	}
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
