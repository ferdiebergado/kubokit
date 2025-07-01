package app

import (
	"database/sql"
	"fmt"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
)

type Provider struct {
	DB        *sql.DB
	Signer    jwt.Signer
	Mailer    email.Mailer
	Validator validation.Validator
	Hasher    hash.Hasher
	Router    router.Router
	CSRFBaker web.Baker
	TxMgr     db.TxManager
}

func newProvider(cfg *config.Config, securityKey string, dbConn *sql.DB) (*Provider, error) {
	signer := jwt.NewGolangJWTSigner(securityKey, cfg.JWT)
	mailer, err := email.NewSMTPMailer(cfg.SMTP, cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("new smtp mailer: %w", err)
	}
	hasher := hash.NewArgon2Hasher(cfg.Argon2, securityKey)
	router := router.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	csrfBaker := security.NewCSRFCookieBaker(cfg.CSRF, securityKey)
	txMgr := db.NewSQLTxManager(dbConn)

	provider := &Provider{
		DB:        dbConn,
		Signer:    signer,
		Hasher:    hasher,
		Mailer:    mailer,
		Router:    router,
		Validator: validator,
		CSRFBaker: csrfBaker,
		TxMgr:     txMgr,
	}

	return provider, nil
}
