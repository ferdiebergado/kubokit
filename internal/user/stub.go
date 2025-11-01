package user

import (
	"context"
	"errors"
)

type StubService struct {
	CreatFunc       func(ctx context.Context, params CreateParams) (User, error)
	FindByEmailFunc func(ctx context.Context, email string) (*User, error)
	ListFunc        func(ctx context.Context) ([]User, error)
	FindFunc        func(ctx context.Context, userID string) (*User, error)
}

var _ Service = &StubService{}

func (s *StubService) List(ctx context.Context) ([]User, error) {
	if s.ListFunc == nil {
		return nil, errors.New("List() not implemented by stub")
	}
	return s.ListFunc(ctx)
}

type StubRepo struct {
	ListFunc        func(ctx context.Context) ([]User, error)
	CreateFunc      func(ctx context.Context, params CreateParams) (User, error)
	FindByEmailFunc func(ctx context.Context, email string) (*User, error)
	FindFunc        func(ctx context.Context, userID string) (*User, error)
}

var _ Repository = &StubRepo{}

func (r *StubRepo) Create(ctx context.Context, params CreateParams) (User, error) {
	if r.CreateFunc == nil {
		return User{}, errors.New("Create() not implemented by stub")
	}
	return r.CreateFunc(ctx, params)
}

func (r *StubRepo) List(ctx context.Context) ([]User, error) {
	if r.ListFunc == nil {
		return nil, errors.New("List() not implemented by stub")
	}
	return r.ListFunc(ctx)
}

func (r *StubRepo) FindByEmail(ctx context.Context, email string) (*User, error) {
	if r.FindByEmailFunc == nil {
		return nil, errors.New("FindByEmail() not implemented by stub")
	}
	return r.FindByEmailFunc(ctx, email)
}

func (r *StubRepo) Find(ctx context.Context, userID string) (*User, error) {
	if r.FindFunc == nil {
		return nil, errors.New("Find() not implemented by stub")
	}
	return r.FindFunc(ctx, userID)
}
