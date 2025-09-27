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
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/pkg/logging"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"
)

const (
	envEnv          = "ENV"
	envLogLevel     = "LOG_LEVEL"
	defaultEnv      = "development"
	defaultLogLevel = "info"

	cfgFile = "config.json"
)

func Run() error {
	appEnv := env.Env(envEnv, defaultEnv)
	logLevel := env.Env(envLogLevel, defaultLogLevel)
	logging.SetupLogger(appEnv, logLevel, os.Stdout)

	slog.Info("Starting server...")

	// TODO: use switch for envs
	if appEnv != "production" {
		if err := env.Load(".env"); err != nil {
			return fmt.Errorf("load env: %w", err)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	dbConn, err := db.NewPostgresDB(signalCtx, cfg.DB)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer dbConn.Close()

	securityKey := cfg.App.Key
	signer, err := jwt.NewGolangJWTSigner(cfg.JWT, securityKey)
	if err != nil {
		return fmt.Errorf("new jwt signer: %w", err)
	}

	mailer, err := email.NewSMTPMailer(cfg.SMTP, cfg.Email)
	if err != nil {
		return fmt.Errorf("new mailer: %w", err)
	}

	hasher, err := hash.NewArgon2Hasher(cfg.Argon2, securityKey)
	if err != nil {
		return fmt.Errorf("new hasher: %w", err)
	}

	validator := validation.NewGoPlaygroundValidator()
	txMgr := db.NewSQLTxManager(dbConn)
	csrfCfg := cfg.CSRF
	csrfCookieBaker := security.NewCSRFCookieBaker(csrfCfg.CookieName, csrfCfg.TokenLen, csrfCfg.MaxAge.Duration)

	userRepo := user.NewRepository(dbConn)
	userService := user.NewService(userRepo, hasher)
	userHandler := user.NewHandler(userService)

	authRepo := auth.NewRepository(dbConn)
	authService, err := auth.NewService(cfg, hasher, mailer, signer, txMgr, authRepo, userService)
	if err != nil {
		return fmt.Errorf("new service: %w", err)
	}

	authHandler, err := auth.NewHandler(cfg.JWT, cfg.Cookie, signer, csrfCookieBaker, authService)
	if err != nil {
		return fmt.Errorf("new auth handler: %w", err)
	}

	middlewares := []func(http.Handler) http.Handler{
		middleware.InjectWriter,
		goexpress.RecoverFromPanic,
		middleware.LogRequest,
		middleware.ContextGuard,
		middleware.CheckContentType,
	}

	api, err := New(cfg, middlewares, signer, validator, authHandler, userHandler)
	if err != nil {
		return fmt.Errorf("new api: %w", err)
	}

	if err = api.Start(signalCtx); err != nil {
		return fmt.Errorf("start server: %w", err)
	}

	if err := api.Shutdown(); err != nil {
		return fmt.Errorf("api shutdown: %w", err)
	}

	slog.Info("Shutdown complete.")

	return nil
}
