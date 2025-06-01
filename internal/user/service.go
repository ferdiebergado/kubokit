package user

import (
	"context"
)

var _ UserService = &Service{}

// UserRepository is the interface for user management.
type UserRepository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	FindUserByEmail(ctx context.Context, email string) (User, error)
}

// Service is the implementation of the User Service interface.
type Service struct {
	repo UserRepository
}

// CreateUser implements UserService.
func (s *Service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	return s.repo.CreateUser(ctx, params)
}

func (s *Service) FindUserByEmail(ctx context.Context, email string) (User, error) {
	return s.repo.FindUserByEmail(ctx, email)
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	return s.repo.ListUsers(ctx)
}

func NewService(repo UserRepository) *Service {
	return &Service{repo}
}
