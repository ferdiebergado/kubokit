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
	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/provider"
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
	userHandler     *user.Handler
	userSvc         user.UserService
	authHandler     *auth.Handler
	shortHasher     security.ShortHasher
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
	cfg := a.config
	maxBodySize := cfg.Server.MaxBodyBytes
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

		gr.Post("/refresh", a.authHandler.RefreshToken, requireToken)

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

func New(providers *provider.Provider, middlewares []func(http.Handler) http.Handler) (*App, error) {
	if providers == nil {
		return nil, errors.New("provider should not be nil")
	}

	cfg := providers.Cfg
	serverCfg := cfg.Server
	handler := middleware.CORS(cfg.CORS)(providers.Router)
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

	userModule := user.NewModule(providers)
	userHandler := userModule.Handler()
	userSvc := userModule.Service()

	authModule, err := auth.NewModule(providers, userSvc)
	if err != nil {
		stop()
		return nil, fmt.Errorf("new auth module: %w", err)
	}
	authHandler := authModule.Handler()

	api := &App{
		config:          cfg,
		db:              providers.DB,
		txManager:       providers.TxMgr,
		signer:          providers.Signer,
		mailer:          providers.Mailer,
		validator:       providers.Validator,
		hasher:          providers.Hasher,
		router:          providers.Router,
		userHandler:     userHandler,
		userSvc:         userSvc,
		authHandler:     authHandler,
		server:          server,
		middlewares:     middlewares,
		stop:            stop,
		shutdownTimeout: serverCfg.ShutdownTimeout.Duration,
		shortHasher:     providers.ShortHasher,
	}

	return api, nil
}
