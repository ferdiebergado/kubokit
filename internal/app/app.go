package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type App struct {
	server          *http.Server
	config          *config.Config
	middlewares     []func(http.Handler) http.Handler
	stop            context.CancelFunc
	shutdownTimeout time.Duration
	db              *sql.DB
	signer          jwt.Signer
	mailer          email.Mailer
	validator       validation.Validator
	hasher          hash.Hasher
	router          router.Router
	txManager       db.TxManager
	csrfBaker       web.Baker
}

func (a *App) registerMiddlewares() {
	for _, mw := range a.middlewares {
		a.router.Use(mw)
	}
}

func (a *App) setupRoutes() {
	userModule := user.NewModule(a.db)
	userHandler := userModule.Handler()
	mountUserRoutes(a.router, userHandler, a.signer)

	authProvider := &auth.Provider{
		Cfg:       a.config,
		DB:        a.db,
		Hasher:    a.hasher,
		Signer:    a.signer,
		Mailer:    a.mailer,
		UserSvc:   userModule.Service(),
		CSRFBaker: a.csrfBaker,
		TXMgr:     a.txManager,
	}
	authModule := auth.NewModule(authProvider)
	authHandler := authModule.Handler()
	mountAuthRoutes(a.router, authHandler, a.validator, authProvider)
}

func (a *App) Start(ctx context.Context) error {
	a.registerMiddlewares()
	a.setupRoutes()

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("Server listening...", "address", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- fmt.Errorf("listen and serve: %w", err)
			return
		}
		slog.Info("Server has stopped.")
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		slog.Info("Shutdown signal received.")
		return nil
	case err := <-serverErr:
		return err
	}
}

func (a *App) Shutdown() error {
	slog.Info("Shutting down server...")
	a.stop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), a.shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}

func New(cfg *config.Config, provider *Provider, middlewares []func(http.Handler) http.Handler) *App {
	serverCtx, stop := context.WithCancel(context.Background())
	serverCfg := cfg.Server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", serverCfg.Port),
		Handler: provider.Router,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  serverCfg.ReadTimeout.Duration,
		WriteTimeout: serverCfg.WriteTimeout.Duration,
		IdleTimeout:  serverCfg.IdleTimeout.Duration,
	}

	return &App{
		config:          cfg,
		db:              provider.DB,
		txManager:       provider.TxMgr,
		signer:          provider.Signer,
		mailer:          provider.Mailer,
		validator:       provider.Validator,
		hasher:          provider.Hasher,
		router:          provider.Router,
		csrfBaker:       provider.CSRFBaker,
		server:          server,
		middlewares:     middlewares,
		stop:            stop,
		shutdownTimeout: serverCfg.ShutdownTimeout.Duration,
	}
}
