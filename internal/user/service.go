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
	Update(ctx context.Context, updates *User, userID string) error
	Delete(ctx context.Context, userID string) error
}

type service struct {
	repo Repository
}

var _ Service = (*service)(nil)

func NewService(repo Repository) Service {
	return &service{
		repo: repo,
	}
}

func (s *service) List(ctx context.Context) ([]User, error) {
	users, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	return users, nil
}
