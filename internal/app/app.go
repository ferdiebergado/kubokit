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

	"github.com/ferdiebergado/slim/internal/auth"
	"github.com/ferdiebergado/slim/internal/config"
	"github.com/ferdiebergado/slim/internal/contract"
	"github.com/ferdiebergado/slim/internal/user"
)

type apiServer struct {
	options     *config.Options
	db          *sql.DB
	router      contract.Router
	server      *http.Server
	middlewares []func(http.Handler) http.Handler
	signer      contract.Signer
	mailer      contract.Mailer
	hasher      contract.Hasher
	stop        context.CancelFunc
}

func newAPIServer(baseCtx context.Context, opts *config.Options, db *sql.DB, signer contract.Signer, mailer contract.Mailer, hasher contract.Hasher, router contract.Router, middlewares []func(http.Handler) http.Handler) *apiServer {
	serverCtx, stop := context.WithCancel(baseCtx)
	serverOpts := opts.Server
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", serverOpts.Port),
		Handler: router,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  time.Duration(serverOpts.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(serverOpts.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(serverOpts.IdleTimeout) * time.Second,
	}

	return &apiServer{
		options:     opts,
		db:          db,
		signer:      signer,
		mailer:      mailer,
		hasher:      hasher,
		router:      router,
		server:      server,
		middlewares: middlewares,
		stop:        stop,
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
	mountAuthRoutes(a.router, authHandler)
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

	shutdownCtx, cancel := context.WithTimeout(baseCtx, time.Duration(a.options.Server.ShutdownTimeout)*time.Second)
	defer cancel()
	if err := a.server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	slog.Info("Shutdown complete.")
	return nil
}
