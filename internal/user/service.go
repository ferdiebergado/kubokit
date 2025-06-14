package user

import (
	"context"
)

var _ UserService = &Service{}

// UserRepository is the interface for user management.
type UserRepository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	FindUserByEmail(ctx context.Context, email string) (*User, error)
}

// Service is the implementation of the User Service interface.
type Service struct {
	repo UserRepository
}

func (s *Service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	u, err := s.repo.CreateUser(ctx, params)
	if err != nil {
		return u, err
	}
	return u, nil
}

func (s *Service) FindUserByEmail(ctx context.Context, email string) (*User, error) {
	u, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return u, err
	}
	return u, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	users, err := s.repo.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func NewService(repo UserRepository) *Service {
	return &Service{repo}
}
