package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/ferdiebergado/goexpress"
	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/pkg/http/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/pkg/validation"
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
		return err
	}

	dbConn, err := db.Connect(signalCtx, cfg.DB)
	if err != nil {
		return err
	}
	defer dbConn.Close()

	securityKey, ok := os.LookupEnv(envKey)
	if !ok {
		return fmt.Errorf(message.EnvErrFmt, envKey)
	}

	providers, err := setupProviders(cfg, securityKey)
	if err != nil {
		return err
	}

	middlewares := []func(http.Handler) http.Handler{
		middleware.InjectWriter,
		goexpress.RecoverFromPanic,
		middleware.LogRequest,
		middleware.CheckContentType,
	}
	apiServer := newAPIServer(signalCtx, cfg, dbConn, providers, middlewares)
	apiErr := apiServer.Start()

	select {
	case <-signalCtx.Done():
		slog.Info("Shutdown signal received.")
	case err := <-apiErr:
		return fmt.Errorf("start server: %w", err)
	}

	return apiServer.Shutdown()
}

func createMailer(cfg *config.Email) (*email.SMTPMailer, error) {
	smtpHost, err := getEnv(envHost)
	if err != nil {
		return nil, err
	}

	smtpPortStr, err := getEnv(envPort)
	if err != nil {
		return nil, err
	}

	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return nil, err
	}

	smtpUser, err := getEnv(envUser)
	if err != nil {
		return nil, err
	}

	smtpPass, err := getEnv(envPass)
	if err != nil {
		return nil, err
	}

	smtpCfg := &email.SMTPConfig{
		User:     smtpUser,
		Password: smtpPass,
		Host:     smtpHost,
		Port:     smtpPort,
	}

	mailer, err := email.NewSMTPMailer(smtpCfg, cfg)
	if err != nil {
		return nil, err
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
	signer := security.NewGolangJWTSigner(securityKey, cfg.JWT)
	mailer, err := createMailer(cfg.Email)
	if err != nil {
		return nil, err
	}
	hasher := security.NewArgon2Hasher(cfg.Argon2, securityKey)
	router := httpx.NewGoexpressRouter()
	validator := validation.NewGoPlaygroundValidator()
	return &Providers{
		Signer:    signer,
		Hasher:    hasher,
		Mailer:    mailer,
		Router:    router,
		Validator: validator,
	}, nil
}
