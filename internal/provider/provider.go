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
	Cfg             *config.Config
	DB              *sql.DB
	Signer          jwt.Signer
	Mailer          email.Mailer
	Validator       validation.Validator
	Hasher          hash.Hasher
	Router          router.Router
	TxMgr           db.TxManager
	ShortHasher     security.ShortHasher
	CSRFCookieBaker web.Baker
	CookieCfg       *config.Cookie
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

	router := router.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	txMgr := db.NewSQLTxManager(dbConn)
	shortHasher := security.NewSHA256Hasher(cfg.App.Key)
	csrfCfg := cfg.CSRF
	csrfCookieBaker := security.NewCSRFCookieBaker(csrfCfg.CookieName, csrfCfg.TokenLen, csrfCfg.MaxAge.Duration)

	provider := &Provider{
		Cfg:             cfg,
		DB:              dbConn,
		Signer:          signer,
		Hasher:          hasher,
		Mailer:          mailer,
		Router:          router,
		Validator:       validator,
		TxMgr:           txMgr,
		ShortHasher:     shortHasher,
		CSRFCookieBaker: csrfCookieBaker,
		CookieCfg:       cfg.Cookie,
	}

	return provider, nil
}
