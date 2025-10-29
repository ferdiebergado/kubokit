package auth

import (
	"context"
	"errors"
	"time"

	"github.com/ferdiebergado/kubokit/internal/user"
)

type StubService struct {
	RegisterFunc                func(ctx context.Context, params RegisterParams) (user.User, error)
	VerifyFunc                  func(ctx context.Context, token string) error
	LoginFunc                   func(ctx context.Context, params LoginParams) (*Session, error)
	SendPasswordResetFunc       func(ctx context.Context, email string) error
	ChangePasswordFunc          func(ctx context.Context, params ChangePasswordParams) error
	ResetPasswordFunc           func(ctx context.Context, params ResetPasswordParams) error
	RefreshTokenFunc            func(token string) (*Session, error)
	ResendVerificationEmailFunc func(ctx context.Context, email string) error
	LogoutFunc                  func(ctx context.Context, token string) error
}

// ResendVerificationEmail implements AuthService.
func (s *StubService) ResendVerificationEmail(ctx context.Context, email string) error {
	if s.ResendVerificationEmailFunc == nil {
		return errors.New("ResendVerificationEmail() not implemented by stub")
	}
	return s.ResendVerificationEmailFunc(ctx, email)
}

func (s StubService) Register(ctx context.Context, params RegisterParams) (user.User, error) {
	if s.RegisterFunc == nil {
		return user.User{}, errors.New("Register() not implemented by stub")
	}
	return s.RegisterFunc(ctx, params)
}

func (s *StubService) Verify(ctx context.Context, token string) error {
	if s.VerifyFunc == nil {
		return errors.New("Verify() not implemented by stub")
	}
	return s.VerifyFunc(ctx, token)
}

func (s *StubService) Login(ctx context.Context, params LoginParams) (*Session, error) {
	if s.LoginFunc == nil {
		return nil, errors.New("Login() not implemented by stub")
	}
	return s.LoginFunc(ctx, params)
}

func (s *StubService) SendPasswordReset(ctx context.Context, email string) error {
	if s.SendPasswordResetFunc == nil {
		return errors.New("SendPasswordReset() not implemented by stub")
	}
	return s.SendPasswordResetFunc(ctx, email)
}

func (s *StubService) ChangePassword(ctx context.Context, params ChangePasswordParams) error {
	if s.ChangePasswordFunc == nil {
		return errors.New("ChangePassword() not implemented by stub")
	}
	return s.ChangePasswordFunc(ctx, params)
}

func (s *StubService) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	if s.ResetPasswordFunc == nil {
		return errors.New("ResetPassword() not implemented by stub")
	}
	return s.ResetPasswordFunc(ctx, params)
}

func (s *StubService) RefreshToken(token string) (*Session, error) {
	if s.RefreshTokenFunc == nil {
		return nil, errors.New("RefreshToken() not implemented by stub")
	}
	return s.RefreshTokenFunc(token)
}

func (s *StubService) Logout(ctx context.Context, token string) error {
	if s.LogoutFunc == nil {
		return errors.New("Logout() not implemented by stub")
	}
	return s.LogoutFunc(ctx, token)
}

var _ Service = &StubService{}

type StubRepo struct {
	RegisterFunc       func(ctx context.Context, params RegisterParams) (user.User, error)
	LoginFunc          func(ctx context.Context, params LoginParams) (accessToken, refreshToken string, err error)
	VerifyFunc         func(ctx context.Context, userID string) error
	ChangePasswordFunc func(ctx context.Context, email, newPassword string) error
}

func (r *StubRepo) Register(ctx context.Context, params RegisterParams) (user.User, error) {
	if r.RegisterFunc == nil {
		return user.User{}, errors.New("Register() not implemented in stub")
	}
	return r.RegisterFunc(ctx, params)
}

func (r *StubRepo) Login(ctx context.Context, params LoginParams) (accessToken, refreshToken string, err error) {
	if r.LoginFunc == nil {
		return "", "", errors.New("Login() not implemented by stub")
	}
	return r.LoginFunc(ctx, params)
}

func (r *StubRepo) Verify(ctx context.Context, userID string) error {
	if r.VerifyFunc == nil {
		return errors.New("Verify() not implemented by stub")
	}
	return r.VerifyFunc(ctx, userID)
}

func (r *StubRepo) ChangePassword(ctx context.Context, email, newPassword string) error {
	if r.ChangePasswordFunc == nil {
		return errors.New("ChangePassword() not implemented by stub")
	}
	return r.ChangePasswordFunc(ctx, email, newPassword)
}

var _ Repository = &StubRepo{}

type StubSigner struct {
	SignFunc   func(subject string, audience []string, duration time.Duration) (string, error)
	VerifyFunc func(tokenString string) (*Claims, error)
}

func (s *StubSigner) Sign(subject string, audience []string, duration time.Duration) (string, error) {
	if s.SignFunc == nil {
		return "", errors.New("Sign not implemented by stub")
	}
	return s.SignFunc(subject, audience, duration)
}

func (s *StubSigner) Verify(tokenString string) (*Claims, error) {
	if s.VerifyFunc == nil {
		return nil, errors.New("Verify not implemented by stub")
	}
	return s.VerifyFunc(tokenString)
}

var _ Signer = &StubSigner{}
