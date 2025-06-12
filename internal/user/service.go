package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var _ UserService = &Service{}

var ErrNotFound = errors.New("user not found")

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

func (s *Service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	u, err := s.repo.CreateUser(ctx, params)
	if err != nil {
		return User{}, fmt.Errorf("failed to create user with email %s: %w", params.Email, err)
	}
	return u, nil
}

func (s *Service) FindUserByEmail(ctx context.Context, email string) (User, error) {
	u, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, fmt.Errorf("user with email %s not found: %w", email, ErrNotFound)
		}
		return User{}, fmt.Errorf("failed to find user by email %s: %w", email, err)
	}
	return u, nil
}

func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	users, err := s.repo.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	return users, nil
}

func NewService(repo UserRepository) *Service {
	return &Service{repo}
}
