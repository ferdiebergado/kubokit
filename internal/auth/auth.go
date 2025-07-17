package auth

import (
	"errors"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/provider"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type Module struct {
	svc     *Service
	handler *Handler
}

func (m *Module) Handler() *Handler {
	return m.handler
}

func (m *Module) Service() *Service {
	return m.svc
}

func NewModule(providers *provider.Provider, userSvc user.UserService) (*Module, error) {
	if providers == nil {
		return nil, errors.New("provider should not be nil")
	}

	repo := NewRepository(providers.DB)
	svc, err := NewService(repo, providers, userSvc)
	if err != nil {
		return nil, fmt.Errorf("new service: %w", err)
	}

	handler, err := NewHandler(svc, providers)
	if err != nil {
		return nil, fmt.Errorf("new auth handler: %w", err)
	}

	module := &Module{
		handler: handler,
		svc:     svc,
	}

	return module, nil
}
