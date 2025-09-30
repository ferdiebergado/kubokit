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
	cfgCORS         *config.CORS
	cfgCSRF         *config.CSRF
	signer          jwt.Signer
	validator       validation.Validator
	router          router.Router
	userHandler     *user.Handler
	authHandler     *auth.Handler
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
	csrfGuard := middleware.CSRFGuard(a.cfgCSRF)
	requireToken := auth.RequireToken(a.signer)

	// auth routes
	a.router.Group("/auth", func(gr router.Router) {
		gr.Post("/register", a.authHandler.RegisterUser,
			middleware.DecodePayload[auth.RegisterUserRequest](maxBodySize),
			middleware.ValidateInput[auth.RegisterUserRequest](a.validator))

		gr.Post("/login", a.authHandler.LoginUser,
			middleware.DecodePayload[auth.UserLoginRequest](maxBodySize),
			middleware.ValidateInput[auth.UserLoginRequest](a.validator))

		gr.Post("/verify", a.authHandler.VerifyUser,
			middleware.DecodePayload[auth.VerifyUserRequest](maxBodySize),
			middleware.ValidateInput[auth.VerifyUserRequest](a.validator))

		gr.Post("/resend-verify-email", a.authHandler.ResendVerifyEmail,
			middleware.DecodePayload[auth.ResendVerifyEmailRequest](maxBodySize),
			middleware.ValidateInput[auth.ResendVerifyEmailRequest](a.validator))

		gr.Post("/refresh", a.authHandler.RefreshToken, csrfGuard)

		gr.Post("/forgot", a.authHandler.ForgotPassword,
			middleware.DecodePayload[auth.ForgotPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ForgotPasswordRequest](a.validator))

		gr.Post("/reset", a.authHandler.ResetPassword,
			auth.VerifyToken(a.signer),
			middleware.DecodePayload[auth.ResetPasswordRequest](maxBodySize),
			middleware.ValidateInput[auth.ResetPasswordRequest](a.validator))
	})

	// users routes
	a.router.Group("/users", func(gr router.Router) {
		gr.Get("/", a.userHandler.ListUsers)
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

type Provider struct {
	CfgServer *config.Server
	CfgCORS   *config.CORS
	CfgCSRF   *config.CSRF
	Router    router.Router
	Signer    jwt.Signer
	Validator validation.Validator
}

func New(provider *Provider, middlewares []func(http.Handler) http.Handler, authHandler *auth.Handler, userHandler *user.Handler) (*App, error) {
	cfgServer := provider.CfgServer
	router := provider.Router
	handler := middleware.CORS(provider.CfgCORS)(router)
	serverCtx, stop := context.WithCancel(context.Background())
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfgServer.Port),
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  cfgServer.ReadTimeout.Duration,
		WriteTimeout: cfgServer.WriteTimeout.Duration,
		IdleTimeout:  cfgServer.IdleTimeout.Duration,
	}

	api := &App{
		server:          server,
		middlewares:     middlewares,
		stop:            stop,
		shutdownTimeout: cfgServer.ShutdownTimeout.Duration,
		cfgServer:       cfgServer,
		cfgCORS:         provider.CfgCORS,
		cfgCSRF:         provider.CfgCSRF,
		signer:          provider.Signer,
		validator:       provider.Validator,
		router:          router,
		userHandler:     userHandler,
		authHandler:     authHandler,
	}

	return api, nil
}
