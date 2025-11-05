package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"
)

type App struct {
	server          *http.Server
	middlewares     []func(http.Handler) http.Handler
	stop            context.CancelFunc
	shutdownTimeout time.Duration
	cfgServer       *config.Server
	signer          jwt.Signer
	validator       validation.Validator
	router          router.Router
	userHandler     *user.Handler
	authHandler     *auth.Handler
}

type Dependencies struct {
	CfgServer   *config.Server
	Router      router.Router
	Signer      jwt.Signer
	Validator   validation.Validator
	Middlewares []func(http.Handler) http.Handler
	AuthHandler *auth.Handler
	UserHandler *user.Handler
}

func New(deps *Dependencies) (*App, error) {
	cfgServer := deps.CfgServer
	router := deps.Router

	serverCtx, stop := context.WithCancel(context.Background())
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfgServer.Port),
		Handler: router,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  cfgServer.ReadTimeout.Duration,
		WriteTimeout: cfgServer.WriteTimeout.Duration,
		IdleTimeout:  cfgServer.IdleTimeout.Duration,
	}

	return &App{
		server:          server,
		middlewares:     deps.Middlewares,
		stop:            stop,
		shutdownTimeout: cfgServer.ShutdownTimeout.Duration,
		cfgServer:       cfgServer,
		signer:          deps.Signer,
		validator:       deps.Validator,
		router:          router,
		userHandler:     deps.UserHandler,
		authHandler:     deps.AuthHandler,
	}, nil
}

func (a *App) registerMiddlewares() {
	if len(a.middlewares) == 0 {
		slog.Warn("No middlewares registered")
		return
	}

	for _, mw := range a.middlewares {
		a.router.Use(mw)
	}
}

func (a *App) setupRoutes() {
	maxBodySize := a.cfgServer.MaxBodyBytes
	requireToken := auth.RequireToken(a.signer)

	// auth routes
	a.router.Group("/auth", func(gr router.Router) {
		gr.Post("/register", a.authHandler.Register,
			middleware.DecodePayload[auth.RegisterRequest](maxBodySize),
			middleware.ValidateInput[auth.RegisterRequest](a.validator))

		gr.Post("/login", a.authHandler.Login,
			middleware.DecodePayload[auth.LoginRequest](maxBodySize),
			middleware.ValidateInput[auth.LoginRequest](a.validator))

		gr.Post("/verify", a.authHandler.Verify,
			middleware.DecodePayload[auth.VerifyRequest](maxBodySize),
			middleware.ValidateInput[auth.VerifyRequest](a.validator))

		gr.Post("/resend-verify-email", a.authHandler.ResendVerifyEmail,
			middleware.DecodePayload[auth.ResendVerifyEmailRequest](maxBodySize),
			middleware.ValidateInput[auth.ResendVerifyEmailRequest](a.validator))

		gr.Post("/refresh", a.authHandler.RefreshToken)

		gr.Post("/forgot", a.authHandler.ForgotPassword,
			middleware.DecodePayload[auth.ForgotPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ForgotPasswordRequest](a.validator))

		gr.Post("/change-password", a.authHandler.ChangePassword,
			requireToken,
			middleware.DecodePayload[auth.ChangePasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ChangePasswordRequest](a.validator))

		gr.Post("/reset", a.authHandler.ResetPassword,
			auth.VerifyToken(a.signer),
			middleware.DecodePayload[auth.ResetPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ResetPasswordRequest](a.validator))

		gr.Post("/logout", a.authHandler.Logout, requireToken)
	})

	// users routes
	a.router.Group("/users", func(gr router.Router) {
		gr.Get("/", a.userHandler.List)
	}, requireToken)
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
