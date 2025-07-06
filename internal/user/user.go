package user

import (
	"github.com/ferdiebergado/kubokit/internal/provider"
)

type Module struct {
	repo    *Repository
	svc     *Service
	handler *Handler
}

func (m *Module) Handler() *Handler {
	return m.handler
}

func (m *Module) Service() *Service {
	return m.svc
}

func NewModule(providers *provider.Provider) *Module {
	repo := NewRepository(providers.DB)
	svc := NewService(repo, providers.Hasher)
	handler := NewHandler(svc)
	return &Module{
		repo:    repo,
		svc:     svc,
		handler: handler,
	}
}
