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

	"github.com/ferdiebergado/kubokit/internal/app/contract"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type Providers struct {
	Signer    contract.Signer
	Mailer    contract.Mailer
	Validator contract.Validator
	Hasher    contract.Hasher
	Router    contract.Router
}

type apiServer struct {
	server          *http.Server
	options         *config.Config
	middlewares     []func(http.Handler) http.Handler
	stop            context.CancelFunc
	shutdownTimeout time.Duration
	db              *sql.DB
	signer          contract.Signer
	mailer          contract.Mailer
	validator       contract.Validator
	hasher          contract.Hasher
	router          contract.Router
}

func newAPIServer(
	baseCtx context.Context,
	cfg *config.Config,
	db *sql.DB, providers *Providers,
	middlewares []func(http.Handler) http.Handler) *apiServer {
	serverCtx, stop := context.WithCancel(baseCtx)
	serverCfg := cfg.Server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", serverCfg.Port),
		Handler: providers.Router,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  serverCfg.ReadTimeout.Duration,
		WriteTimeout: serverCfg.WriteTimeout.Duration,
		IdleTimeout:  serverCfg.IdleTimeout.Duration,
	}

	return &apiServer{
		options:         cfg,
		db:              db,
		signer:          providers.Signer,
		mailer:          providers.Mailer,
		validator:       providers.Validator,
		hasher:          providers.Hasher,
		router:          providers.Router,
		server:          server,
		middlewares:     middlewares,
		stop:            stop,
		shutdownTimeout: serverCfg.ShutdownTimeout.Duration,
	}
}

func (a *apiServer) registerMiddlewares() {
	for _, mw := range a.middlewares {
		a.router.Use(mw)
	}
}

func (a *apiServer) setupRoutes() {
	userRepo := user.NewRepository(a.db)
	userService := user.NewService(userRepo)
	userHandler := user.NewHandler(userService)
	mountUserRoutes(a.router, userHandler, a.signer)

	authRepo := auth.NewRepository(a.db)
	authProviders := &auth.Providers{
		Hasher: a.hasher,
		Signer: a.signer,
		Mailer: a.mailer,
	}
	authService := auth.NewService(authRepo, authProviders, a.options)
	authHandler := auth.NewHandler(authService, a.signer, a.options)
	mountAuthRoutes(a.router, authHandler, a.validator, a.options.Server.MaxBodyBytes)
}

func (a *apiServer) Start() chan error {
	a.registerMiddlewares()
	a.setupRoutes()

	serverErr := make(chan error)
	go func() {
		slog.Info("Server listening...", "address", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()
	return serverErr
}

func (a *apiServer) Shutdown(baseCtx context.Context) error {
	slog.Info("Server shutting down...")
	defer a.stop()

	shutdownCtx, cancel := context.WithTimeout(baseCtx, a.shutdownTimeout)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	slog.Info("Shutdown complete.")
	return nil
}
