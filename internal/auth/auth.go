package auth

import (
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

func NewModule(provider *provider.Provider, userSvc user.UserService) *Module {
	repo := NewRepository(provider.DB)
	svc := NewService(repo, provider, userSvc)
	handler := NewHandler(svc, provider)
	return &Module{
		handler: handler,
		svc:     svc,
	}
}
