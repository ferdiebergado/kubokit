package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ferdiebergado/goexpress"
	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
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

func Run() error {
	slog.Info("Starting server...")

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	if os.Getenv(envEnv) != "production" {
		if err := env.Load(".env"); err != nil {
			return fmt.Errorf("load env: %w", err)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	dbConn, err := db.NewPostgresDB(signalCtx, cfg.DB)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer dbConn.Close()

	securityKey, ok := os.LookupEnv(envKey)
	if !ok {
		return fmt.Errorf(message.EnvErrFmt, envKey)
	}

	provider, err := newProvider(cfg, securityKey, dbConn)
	if err != nil {
		return fmt.Errorf("setup providers: %w", err)
	}

	middlewares := []func(http.Handler) http.Handler{
		middleware.InjectWriter,
		goexpress.RecoverFromPanic,
		middleware.LogRequest,
		middleware.ContextGuard,
		middleware.CheckContentType,
	}

	//nolint:contextcheck //This function internally creates a context with cancel.
	api := New(cfg, dbConn, provider, middlewares)
	if err = api.Start(signalCtx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	//nolint:contextcheck //This function internally passes a context with timeout to the underlying http.Server Shutdown method.
	if err := api.Shutdown(); err != nil {
		return fmt.Errorf("api shutdown: %w", err)
	}

	slog.Info("Shutdown complete.")

	return nil
}

func getEnv(envVar string) (string, error) {
	val, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf(message.EnvErrFmt, val)
	}
	return val, nil
}
