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
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/provider"
)

const (
	envEnv      = "ENV"
	envLogLevel = "LOG_LEVEL"

	cfgFile = "config.json"
)

func Run() error {
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	appEnv := os.Getenv(envEnv)
	logLevel := os.Getenv(envLogLevel)

	logging.SetupLogger(appEnv, logLevel, os.Stdout)

	slog.Info("Starting server...")

	if appEnv != "production" {
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

	providers, err := provider.New(cfg, dbConn)
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

	api := New(providers, middlewares)
	if err = api.Start(signalCtx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	if err := api.Shutdown(); err != nil {
		return fmt.Errorf("api shutdown: %w", err)
	}

	slog.Info("Shutdown complete.")

	return nil
}
