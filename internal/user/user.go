package user

import "github.com/ferdiebergado/kubokit/internal/platform/db"

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

func NewModule(dbExec db.Executor) *Module {
	repo := NewRepository(dbExec)
	svc := NewService(repo)
	handler := NewHandler(svc)
	return &Module{
		repo:    repo,
		svc:     svc,
		handler: handler,
	}
}
