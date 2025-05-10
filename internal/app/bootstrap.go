package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ferdiebergado/goexpress"
	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/slim/internal/config"
	"github.com/ferdiebergado/slim/internal/contract"
	"github.com/ferdiebergado/slim/internal/db"
	"github.com/ferdiebergado/slim/internal/email"
	httpx "github.com/ferdiebergado/slim/internal/http"
	"github.com/ferdiebergado/slim/internal/middleware"
	"github.com/ferdiebergado/slim/internal/security"
)

func Run(baseCtx context.Context) error {
	slog.Info("Initializing...")

	signalCtx, stop := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	defer stop()

	if os.Getenv("ENV") != "production" {
		if err := env.Load(".env"); err != nil {
			return fmt.Errorf("load env: %w", err)
		}
	}

	opts, err := config.New("config.json")
	if err != nil {
		return err
	}

	dbConn, err := db.Connect(signalCtx, opts.DB)
	if err != nil {
		return err
	}
	defer dbConn.Close()

	securityKey := os.Getenv("KEY")
	if securityKey == "" {
		return errors.New("environment variable KEY is not set")
	}
	signer := security.NewSigner(securityKey, opts.JWT)
	mailer, err := createMailer(opts.Email)
	if err != nil {
		return err
	}
	hasher := security.NewArgon2Hasher(opts.Argon2, securityKey)
	router := httpx.NewGoexpressRouter()
	middlewares := []func(http.Handler) http.Handler{
		middleware.InjectWriter,
		goexpress.RecoverFromPanic,
		middleware.LogRequest,
	}
	apiServer := newAPIServer(baseCtx, opts, dbConn, signer, mailer, hasher, router, middlewares)
	apiErr := apiServer.Start()

	select {
	case <-signalCtx.Done():
		slog.Info("Shutdown signal received.")
		stop()
	case err := <-apiErr:
		return fmt.Errorf("start server: %w", err)
	}

	return apiServer.Shutdown(baseCtx)
}

func createMailer(opts *config.EmailOptions) (contract.Mailer, error) {
	const fmtErr = "%s environment variable is not set"
	const (
		envUser = "SMTP_USER"
		envPass = "SMTP_PASS"
		envHost = "SMTP_HOST"
		envPort = "SMTP_PORT"
	)

	smtpUser, ok := os.LookupEnv(envUser)
	if !ok {
		return nil, fmt.Errorf(fmtErr, envUser)
	}

	smtpPass, ok := os.LookupEnv(envPass)
	if !ok {
		return nil, fmt.Errorf(fmtErr, envPass)
	}

	smtpHost, ok := os.LookupEnv(envHost)
	if !ok {
		return nil, fmt.Errorf(fmtErr, envHost)
	}

	smtpPortStr, ok := os.LookupEnv(envPort)
	if !ok {
		return nil, fmt.Errorf(fmtErr, envPort)
	}

	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return nil, err
	}

	smtpCfg := &email.SMTPConfig{
		User:     smtpUser,
		Password: smtpPass,
		Host:     smtpHost,
		Port:     smtpPort,
	}

	mailer, err := email.NewSMTPMailer(smtpCfg, opts)
	if err != nil {
		return nil, err
	}
	return mailer, nil
}
