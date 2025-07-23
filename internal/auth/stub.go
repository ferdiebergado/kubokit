package auth

import (
	"context"
	"errors"

	"github.com/ferdiebergado/kubokit/internal/user"
)

type StubService struct {
	RegisterUserFunc      func(ctx context.Context, params RegisterUserParams) (user.User, error)
	VerifyUserfunc        func(ctx context.Context, token string) error
	LoginUserFunc         func(ctx context.Context, params LoginUserParams) (*AuthData, error)
	SendPasswordResetFunc func(email string)
	ResetPasswordFunc     func(ctx context.Context, params ResetPasswordParams) error
	RefreshTokenFunc      func(token string) (*AuthData, error)
}

func (s StubService) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	if s.RegisterUserFunc == nil {
		return user.User{}, errors.New("RegisterUser not implemented by stub")
	}
	return s.RegisterUserFunc(ctx, params)
}

func (s *StubService) VerifyUser(ctx context.Context, token string) error {
	if s.VerifyUserfunc == nil {
		return errors.New("VerifyUser not implemented by stub")
	}
	return s.VerifyUserfunc(ctx, token)
}

func (s *StubService) LoginUser(ctx context.Context, params LoginUserParams) (*AuthData, error) {
	if s.LoginUserFunc == nil {
		return nil, errors.New("LoginUser not implemented by stub")
	}
	return s.LoginUserFunc(ctx, params)
}

func (s *StubService) SendPasswordReset(email string) {
	if s.SendPasswordResetFunc == nil {
		panic("SendPasswordReset not implemented by stub")
	}
	s.SendPasswordResetFunc(email)
}

func (s *StubService) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	if s.ResetPasswordFunc == nil {
		return errors.New("ResetPassword not implemented by stub")
	}
	return s.ResetPasswordFunc(ctx, params)
}

func (s *StubService) RefreshToken(token string) (*AuthData, error) {
	if s.RefreshTokenFunc == nil {
		return nil, errors.New("RefreshToken not implemented by stub")
	}
	return s.RefreshTokenFunc(token)
}

type StubRepo struct {
	RegisterUserFunc       func(ctx context.Context, params RegisterUserParams) (user.User, error)
	LoginUserFunc          func(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error)
	VerifyUserFunc         func(ctx context.Context, userID string) error
	ChangeUserPasswordFunc func(ctx context.Context, email, newPassword string) error
}

func (r *StubRepo) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	if r.RegisterUserFunc == nil {
		return user.User{}, errors.New("RegisterUser not implemented in stub")
	}
	return r.RegisterUserFunc(ctx, params)
}

func (r *StubRepo) LoginUser(ctx context.Context, params LoginUserParams) (accessToken, refreshToken string, err error) {
	if r.LoginUserFunc == nil {
		return "", "", errors.New("LoginUser not implemented by stub")
	}
	return r.LoginUserFunc(ctx, params)
}

func (r *StubRepo) VerifyUser(ctx context.Context, userID string) error {
	if r.VerifyUserFunc == nil {
		return errors.New("VerifyUser not implemented by stub")
	}
	return r.VerifyUserFunc(ctx, userID)
}

func (r *StubRepo) ChangeUserPassword(ctx context.Context, email, newPassword string) error {
	if r.ChangeUserPasswordFunc == nil {
		return errors.New("ChangeUserPassword not implemented by stub")
	}
	return r.ChangeUserPasswordFunc(ctx, email, newPassword)
}
