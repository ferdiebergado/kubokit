package user

import (
	"context"
)

var _ Service = &service{}

type Repository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return &service{repo}
}

func (s *service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	return s.repo.CreateUser(ctx, params)
}

func (s *service) FindUserByEmail(ctx context.Context, email string) (User, error) {
	return s.repo.FindUserByEmail(ctx, email)
}

func (s *service) ListUsers(ctx context.Context) ([]User, error) {
	return s.repo.ListUsers(ctx)
}
