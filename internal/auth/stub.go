package auth

import (
	"context"
	"errors"

	"github.com/ferdiebergado/kubokit/internal/user"
)

type StubService struct {
	RegisterUserFunc func(ctx context.Context, params RegisterUserParams) (user.User, error)
}

func (s StubService) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	if s.RegisterUserFunc == nil {
		return user.User{}, errors.New("RegisterUser not implemented by stub")
	}
	return s.RegisterUserFunc(ctx, params)
}

func (s *StubService) VerifyUser(ctx context.Context, token string) error {
	panic("not implemented") // TODO: Implement
}

func (s *StubService) LoginUser(ctx context.Context, params LoginUserParams) (accessToken string, refreshToken string, err error) {
	panic("not implemented") // TODO: Implement
}

func (s *StubService) SendPasswordReset(email string) {
	panic("not implemented") // TODO: Implement
}

func (s *StubService) ResetPassword(ctx context.Context, params ResetPasswordParams) error {
	panic("not implemented") // TODO: Implement
}

type StubRepo struct {
	RegisterUserFunc func(ctx context.Context, params RegisterUserParams) (user.User, error)
}

func (r *StubRepo) RegisterUser(ctx context.Context, params RegisterUserParams) (user.User, error) {
	if r.RegisterUserFunc == nil {
		return user.User{}, errors.New("RegisterUser not implemented in stub")
	}
	return r.RegisterUserFunc(ctx, params)
}

func (r *StubRepo) LoginUser(ctx context.Context, params LoginUserParams) (accessToken string, refreshToken string, err error) {
	panic("not implemented") // TODO: Implement
}

func (r *StubRepo) VerifyUser(ctx context.Context, userID string) error {
	panic("not implemented") // TODO: Implement
}

func (r *StubRepo) ChangeUserPassword(ctx context.Context, email string, newPassword string) error {
	panic("not implemented") // TODO: Implement
}
