package auth

import (
	"database/sql"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type Providers struct {
	Cfg     *config.Config
	DB      *sql.DB
	Hasher  hash.Hasher
	Signer  jwt.Signer
	Mailer  email.Mailer
	UserSvc user.UserService
	Baker   web.Baker
	TXMgr   db.TxManager
}

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

func NewModule(providers *Providers) *Module {
	repo := NewRepository(providers.DB)
	svc := NewService(repo, providers)
	handler := NewHandler(svc, providers)
	return &Module{
		handler: handler,
		svc:     svc,
	}
}
