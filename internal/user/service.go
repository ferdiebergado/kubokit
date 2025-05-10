package user

import (
	"context"
)

type repo interface {
	GetAllUsers(ctx context.Context) ([]User, error)
}

type Service struct {
	repo repo
}

func NewService(repo repo) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) GetAllUsers(ctx context.Context) ([]User, error) {
	return s.repo.GetAllUsers(ctx)
}
