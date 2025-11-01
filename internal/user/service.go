package user

import (
	"context"
)

// Repository is the interface for user management.
type Repository interface {
	Create(ctx context.Context, params CreateParams) (User, error)
	List(ctx context.Context) ([]User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	Find(ctx context.Context, userID string) (*User, error)
}

// service is the implementation of the User service interface.
type service struct {
	repo Repository
}

func NewService(repo Repository) *service {
	return &service{
		repo: repo,
	}
}

var _ Service = &service{}

func (s *service) List(ctx context.Context) ([]User, error) {
	users, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	return users, nil
}
