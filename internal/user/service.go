package user

import (
	"context"

	"github.com/ferdiebergado/kubokit/internal/pkg/security"
)

// Repository is the interface for user management.
type Repository interface {
	Create(ctx context.Context, params CreateUserParams) (User, error)
	List(ctx context.Context) ([]User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	Find(ctx context.Context, userID string) (*User, error)
}

// service is the implementation of the User service interface.
type service struct {
	repo   Repository
	hasher *security.Argon2Hasher
}

func (s *service) List(ctx context.Context) ([]User, error) {
	users, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func NewService(repo Repository, hasher *security.Argon2Hasher) *service {
	return &service{
		repo:   repo,
		hasher: hasher,
	}
}

var _ Service = &service{}
