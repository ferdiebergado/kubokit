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
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	mockEmail    = "test@example.com"
	mockPassword = "test"
	mockAppEmail = "app@example.com"
	mockHashed   = "hashed"
)

var (
	errMockRepoFailure = errors.New("query failed")

	now = time.Now()

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
			return mockHashed, nil
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
						return mockHashed, nil
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

	signer := &auth.StubSigner{
		SignFunc: func(claims map[string]any, ttl time.Duration) (string, error) {
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

	if session == nil {
		t.Fatalf("session = %v, want: not nil", session)
	}

	if session.AccessToken != mockToken {
		t.Errorf("session.AccessToken = %q, want: %q", session.AccessToken, mockToken)
	}

	if session.RefreshToken != mockToken {
		t.Errorf("session.RefreshToken = %q, want: %q", session.RefreshToken, mockToken)
	}

	wantExp := now.Add(mockJWTCfg.TTL.Duration).Unix()
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
			return mockHashed, nil
		},
	}

	signer := &auth.StubSigner{
		SignFunc: func(claims map[string]any, ttl time.Duration) (string, error) {
			return "mock_token", nil
		},
	}

	mockDeps := &auth.Dependencies{
		Repo:     &auth.StubRepo{},
		CfgApp:   mockAppCfg,
		CfgJWT:   mockJWTCfg,
		CfgEmail: mockEmailCfg,
		Hasher:   hasher,
		Mailer:   createMailer(t),
		Signer:   signer,
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
						return mockHashed, nil
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
						return mockHashed, nil
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

			signer := &auth.StubSigner{
				VerifyFunc: func(token string) (map[string]any, error) {
					return map[string]any{
						"sub":     "1",
						"purpose": "verify",
					}, nil
				},
			}

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

			if err := svc.Verify(t.Context(), "mock_token"); err != nil {
				t.Errorf("svc.Verify(t.Context(), mockToken) = %v, want: %v", err, nil)
			}
		})
	}
}

func TestService_VerifyFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "invalid verification token",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					VerifyFunc: func(ctx context.Context, userID string) error {
						return nil
					},
				},
				CfgApp:   &config.App{},
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return nil, errors.New("invalid token")
					},
				},
				Txmgr: &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
					},
				},
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "user does not exist",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub":     "1",
							"purpose": "verify",
						}, nil
					},
				},
				Txmgr: &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "repo failure",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					VerifyFunc: func(ctx context.Context, userID string) error {
						return errMockRepoFailure
					},
				},
				CfgApp:   &config.App{},
				CfgJWT:   &config.JWT{},
				CfgEmail: &config.Email{},
				Hasher:   nil,
				Mailer:   &email.SMTPMailer{},
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub":     "1",
							"purpose": "verify",
						}, nil
					},
				},
				Txmgr: &db.TxManager{},
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
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
			err := svc.Verify(t.Context(), "mock_token")
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
			return mockHashed, nil
		},
	}

	signer := &auth.StubSigner{
		VerifyFunc: func(token string) (map[string]any, error) {
			return map[string]any{
				"sub":     "1",
				"purpose": "reset",
			}, nil
		},
	}

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
	mockParams := auth.ResetPasswordParams{
		Token:    "mock_token",
		Password: "test",
	}

	if err := svc.ResetPassword(t.Context(), mockParams); err != nil {
		t.Errorf("svc.ResetPassword(t.Context(), %+v) = %v, want: %v", mockParams, err, nil)
	}
}

func TestService_ResetPasswordFails(t *testing.T) {
	t.Parallel()

	validClaim := map[string]any{
		"sub":     "1",
		"purpose": "reset",
	}

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "user not found",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return auth.ErrUserNotFound
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   nil,
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return validClaim, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
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
				CfgJWT:   nil,
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return nil, errors.New("invalid token")
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "missing purpose claim",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return nil
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   nil,
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub": "1",
						}, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "incorrect purpose claim",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return nil
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   nil,
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub":     "1",
							"purpose": "verify",
						}, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "missing sub claim",
			deps: &auth.Dependencies{
				Repo: &auth.StubRepo{
					ChangePasswordFunc: func(ctx context.Context, email, newPassword string) error {
						return nil
					},
				},
				CfgApp:   mockAppCfg,
				CfgJWT:   nil,
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"purpose": "reset",
						}, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidSubject,
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
				CfgEmail: nil,
				Hasher: &auth.StubHasher{
					HashFunc: func(plain string) (string, error) {
						return mockHashed, nil
					},
				},
				Mailer: nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return validClaim, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: errMockRepoFailure,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := auth.NewService(tt.deps)

			params := auth.ResetPasswordParams{
				Token:    "mock_token",
				Password: mockPassword,
			}

			err := svc.ResetPassword(t.Context(), params)
			if err == nil {
				t.Fatal("svc.ResetPassword did not return an error")
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("svc.ResetPassword(t.Context(), %+v) = %v, want %v", params, err, tt.wantErr)
			}
		})
	}
}

func TestService_RefreshTokenSuccess(t *testing.T) {
	t.Parallel()

	const refreshToken = "new_mock_refresh_token"

	signer := &auth.StubSigner{
		VerifyFunc: func(token string) (map[string]any, error) {
			return map[string]any{
				"sub":     mockUser.ID,
				"purpose": "refresh",
			}, nil
		},
		SignFunc: func(claims map[string]any, ttl time.Duration) (string, error) {
			return refreshToken, nil
		},
	}

	userRepo := &user.StubRepo{
		FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
			return &mockUser, nil
		},
	}

	deps := &auth.Dependencies{
		Repo:     nil,
		CfgApp:   &config.App{},
		CfgJWT:   mockJWTCfg,
		CfgEmail: nil,
		Hasher:   nil,
		Mailer:   nil,
		Signer:   signer,
		Txmgr:    nil,
		UserRepo: userRepo,
	}

	svc := auth.NewService(deps)
	const mockToken = "mock_refresh_token"
	session, err := svc.RefreshToken(t.Context(), mockToken)
	if err != nil {
		t.Fatalf("err = %v, want: %v", err, nil)
	}

	if session == nil {
		t.Fatalf("session = %v, want: not nil", session)
	}

	if session.AccessToken != refreshToken {
		t.Errorf("session.AccessToken = %q, want: %q", session.AccessToken, refreshToken)
	}

	if session.RefreshToken != refreshToken {
		t.Errorf("session.RefreshToken = %q, want: %q", session.RefreshToken, refreshToken)
	}

	wantExp := now.Add(mockJWTCfg.TTL.Duration).Unix()
	if session.ExpiresIn < wantExp {
		t.Errorf("session.ExpiresIn = %d, want: > %d", session.ExpiresIn, wantExp)
	}

	if session.TokenType != auth.TokenType {
		t.Errorf("session.TokenType = %q, want: %q", session.TokenType, auth.TokenType)
	}

	wantUser := auth.UserInfo{
		ID:    mockUser.ID,
		Email: mockEmail,
	}

	if !reflect.DeepEqual(*session.User, wantUser) {
		t.Errorf("session.User = %+v, want: %+v", *session.User, wantUser)
	}
}

func TestService_RefreshTokenFails(t *testing.T) {
	t.Parallel()

	errSignerFailed := errors.New("failed to sign token")

	validClaim := map[string]any{
		"sub":     mockUser.ID,
		"purpose": "refresh",
	}

	tests := []struct {
		name    string
		deps    *auth.Dependencies
		wantErr error
	}{
		{
			name: "invalid token",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return nil, errors.New("malformed token")
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "missing purpose claim",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub": mockUser.ID,
						}, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "incorrect purpose claim",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return map[string]any{
							"sub":     mockUser.ID,
							"purpose": "session",
						}, nil
					},
				},
				Txmgr:    nil,
				UserRepo: nil,
			},
			wantErr: auth.ErrInvalidToken,
		},
		{
			name: "user not found",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return validClaim, nil
					},
				},
				Txmgr: nil,
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return nil, user.ErrNotFound
					},
				},
			},
			wantErr: auth.ErrUserNotFound,
		},
		{
			name: "repo failure",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return validClaim, nil
					},
				},
				Txmgr: nil,
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return nil, errMockRepoFailure
					},
				},
			},
			wantErr: errMockRepoFailure,
		},
		{
			name: "signing error",
			deps: &auth.Dependencies{
				Repo:     nil,
				CfgApp:   &config.App{},
				CfgJWT:   mockJWTCfg,
				CfgEmail: nil,
				Hasher:   nil,
				Mailer:   nil,
				Signer: &auth.StubSigner{
					VerifyFunc: func(token string) (map[string]any, error) {
						return validClaim, nil
					},
					SignFunc: func(claims map[string]any, ttl time.Duration) (string, error) {
						return "", errSignerFailed
					},
				},
				Txmgr: nil,
				UserRepo: &user.StubRepo{
					FindFunc: func(ctx context.Context, userID string) (*user.User, error) {
						return &mockUser, nil
					},
				},
			},
			wantErr: errSignerFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			svc := auth.NewService(tt.deps)
			const mockToken = "mock_refresh_token"
			_, err := svc.RefreshToken(t.Context(), mockToken)
			if err == nil {
				t.Fatalf("err = %v, want: %v", err, tt.wantErr)
			}

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want: %v", err, tt.wantErr)
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
