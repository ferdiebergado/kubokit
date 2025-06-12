package user

import (
	"context"
	"errors"
)

type StubService struct {
	CreateUserFunc      func(ctx context.Context, params CreateUserParams) (User, error)
	FindUserByEmailFunc func(ctx context.Context, email string) (*User, error)
	ListUsersFunc       func(ctx context.Context) ([]User, error)
}

func (s *StubService) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	if s.CreateUserFunc == nil {
		return User{}, errors.New("CreateUser not implemented in stub")
	}

	return s.CreateUserFunc(ctx, params)
}

func (s *StubService) ListUsers(ctx context.Context) ([]User, error) {
	if s.ListUsersFunc == nil {
		return nil, errors.New("ListUsers not implemented by stub")
	}
	return s.ListUsersFunc(ctx)
}

func (s *StubService) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	if s.FindUserByEmailFunc == nil {
		return nil, errors.New("FindUserByEmail not implemented in stub")
	}
	return s.FindUserByEmailFunc(ctx, email)
}

type StubRepo struct {
	ListUsersFunc       func(ctx context.Context) ([]User, error)
	CreateUserFunc      func(ctx context.Context, params CreateUserParams) (User, error)
	FindUserByEmailFunc func(ctx context.Context, email string) (User, error)
}

func (r *StubRepo) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	if r.CreateUserFunc == nil {
		return User{}, errors.New("CreateUser not implemented by stub")
	}
	return r.CreateUserFunc(ctx, params)
}

func (r *StubRepo) ListUsers(ctx context.Context) ([]User, error) {
	if r.ListUsersFunc == nil {
		return nil, errors.New("ListUsers not implemented by stub")
	}
	return r.ListUsersFunc(ctx)
}

func (r *StubRepo) FindUserByEmail(ctx context.Context, email string) (User, error) {
	if r.FindUserByEmailFunc == nil {
		return User{}, errors.New("FindUserByEmail not implemented by stub")
	}
	return r.FindUserByEmailFunc(ctx, email)
}
