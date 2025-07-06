package provider

import (
	"database/sql"
	"errors"
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
	Cfg       *config.Config
	DB        *sql.DB
	Signer    jwt.Signer
	Mailer    email.Mailer
	Validator validation.Validator
	Hasher    hash.Hasher
	Router    router.Router
	CSRFBaker web.Baker
	TxMgr     db.TxManager
}

func New(cfg *config.Config, dbConn *sql.DB) (*Provider, error) {
	if cfg == nil || dbConn == nil {
		return nil, errors.New("config and dbconn should not be nil")
	}

	securityKey := cfg.App.Key
	signer, err := jwt.NewGolangJWTSigner(cfg.JWT, securityKey)
	if err != nil {
		return nil, fmt.Errorf("new jwt signer: %w", err)
	}
	mailer, err := email.NewSMTPMailer(cfg.SMTP, cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("new mailer: %w", err)
	}
	hasher, err := hash.NewArgon2Hasher(cfg.Argon2, securityKey)
	if err != nil {
		return nil, fmt.Errorf("new hasher: %w", err)
	}
	csrfBaker, err := security.NewCSRFCookieBaker(cfg.CSRF, securityKey)
	if err != nil {
		return nil, fmt.Errorf("new csrf baker: %w", err)
	}

	router := router.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	txMgr := db.NewSQLTxManager(dbConn)

	provider := &Provider{
		Cfg:       cfg,
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
