package app

import (
	"database/sql"
	"fmt"
	"strconv"

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
	Baker     web.Baker
	TxMgr     db.TxManager
}

func newProvider(cfg *config.Config, securityKey string, dbConn *sql.DB) (*Provider, error) {
	signer := jwt.NewGolangJWTSigner(securityKey, cfg.JWT)
	mailer, err := createMailer(cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("create mailer: %w", err)
	}
	hasher := hash.NewArgon2Hasher(cfg.Argon2, securityKey)
	router := router.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	baker := security.NewCSRFCookieBaker(cfg.CSRF)
	txMgr := db.NewSQLTxManager(dbConn)

	provider := &Provider{
		DB:        dbConn,
		Signer:    signer,
		Hasher:    hasher,
		Mailer:    mailer,
		Router:    router,
		Validator: validator,
		Baker:     baker,
		TxMgr:     txMgr,
	}

	return provider, nil
}

func createMailer(cfg *config.Email) (*email.SMTPMailer, error) {
	const errFmt = "get env %q: %w"
	smtpHost, err := getEnv(envHost)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envHost, err)
	}

	smtpPortStr, err := getEnv(envPort)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envPort, err)
	}

	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return nil, fmt.Errorf("convert smtp port string to int: %w", err)
	}

	smtpUser, err := getEnv(envUser)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envUser, err)
	}

	smtpPass, err := getEnv(envPass)
	if err != nil {
		return nil, fmt.Errorf(errFmt, envPass, err)
	}

	smtpCfg := &email.SMTPConfig{
		User:     smtpUser,
		Password: smtpPass,
		Host:     smtpHost,
		Port:     smtpPort,
	}

	mailer, err := email.NewSMTPMailer(smtpCfg, cfg)
	if err != nil {
		return nil, fmt.Errorf("create smtp mailer: %w", err)
	}
	return mailer, nil
}
