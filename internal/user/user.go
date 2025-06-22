package user

import (
	"database/sql"
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

func NewModule(db *sql.DB) *Module {
	repo := NewRepository(db)
	svc := NewService(repo)
	handler := NewHandler(svc)
	return &Module{
		repo:    repo,
		svc:     svc,
		handler: handler,
	}
}
