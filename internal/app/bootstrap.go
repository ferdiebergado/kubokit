package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/ferdiebergado/goexpress"
	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
)

const (
	envEnv  = "ENV"
	envKey  = "KEY"
	envHost = "SMTP_HOST"
	envPort = "SMTP_PORT"
	envUser = "SMTP_USER"
	envPass = "SMTP_PASS"

	cfgFile = "config.json"
)

func Run(signalCtx context.Context) error {
	if envEnv != "production" {
		if err := env.Load(".env"); err != nil {
			return fmt.Errorf("load env: %w", err)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dbConn, err := db.NewConnection(signalCtx, cfg.DB)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer dbConn.Close()

	securityKey, ok := os.LookupEnv(envKey)
	if !ok {
		return fmt.Errorf(message.EnvErrFmt, envKey)
	}

	providers, err := setupProviders(cfg, securityKey)
	if err != nil {
		return fmt.Errorf("setup providers: %w", err)
	}

	middlewares := []func(http.Handler) http.Handler{
		middleware.InjectWriter,
		goexpress.RecoverFromPanic,
		middleware.LogRequest,
		middleware.CheckContentType,
	}

	//nolint:contextcheck //This function internally creates a context with cancel.
	api := New(cfg, dbConn, providers, middlewares)
	if err = api.Start(signalCtx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	//nolint:contextcheck //This function internally passes a context with timeout to the underlying http.Server Shutdown method.
	if err := api.Shutdown(); err != nil {
		return fmt.Errorf("api shutdown: %w", err)
	}

	return nil
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

func getEnv(envVar string) (string, error) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf(message.EnvErrFmt, val)
	}
	return val, nil
}

func setupProviders(cfg *config.Config, securityKey string) (*Providers, error) {
	signer := jwt.NewGolangJWTSigner(securityKey, cfg.JWT)
	mailer, err := createMailer(cfg.Email)
	if err != nil {
		return nil, fmt.Errorf("create mailer: %w", err)
	}
	hasher := hash.NewArgon2Hasher(cfg.Argon2, securityKey)
	router := router.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	return &Providers{
		Signer:    signer,
		Hasher:    hasher,
		Mailer:    mailer,
		Router:    router,
		Validator: validator,
	}, nil
}
