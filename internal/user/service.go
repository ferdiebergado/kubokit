package user

import (
	"context"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/platform/hash"
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
	repo   UserRepository
	hasher hash.Hasher
}

func (s *Service) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	hash, err := s.hasher.Hash(params.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	params.Password = hash
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

func NewService(repo UserRepository, hasher hash.Hasher) *Service {
	return &Service{
		repo:   repo,
		hasher: hasher,
	}
}
