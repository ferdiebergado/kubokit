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
	cfg             *config.Config
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
	cfg := a.cfg
	maxBodySize := cfg.Server.MaxBodyBytes
	csrfGuard := middleware.CSRFGuard(cfg.CSRF)
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

func New(cfg *config.Config, middlewares []func(http.Handler) http.Handler, signer jwt.Signer, validator validation.Validator, authHandler *auth.Handler, userHandler *user.Handler) (*App, error) {
	serverCfg := cfg.Server
	router := router.NewGoexpressRouter()
	handler := middleware.CORS(cfg.CORS)(router)
	serverCtx, stop := context.WithCancel(context.Background())
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", serverCfg.Port),
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return serverCtx
		},
		ReadTimeout:  serverCfg.ReadTimeout.Duration,
		WriteTimeout: serverCfg.WriteTimeout.Duration,
		IdleTimeout:  serverCfg.IdleTimeout.Duration,
	}

	api := &App{
		server:          server,
		middlewares:     middlewares,
		stop:            stop,
		shutdownTimeout: serverCfg.ShutdownTimeout.Duration,
		cfg:             cfg,
		signer:          signer,
		validator:       validator,
		router:          router,
		userHandler:     userHandler,
		authHandler:     authHandler,
	}

	return api, nil
}
