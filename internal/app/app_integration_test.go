//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/app"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/email"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/pkg/security"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupApp(t *testing.T) (server *app.App, cleanUpFunc func()) {
	t.Helper()

	if err := env.Load("../../.env.testing"); err != nil {
		t.Fatalf("load env: %v", err)
	}

	// Load config, using defaults or a test config
	cfg, err := config.Load("../../config.json")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	conn, err := db.NewPostgresDB(context.Background(), cfg.DB)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}

	signer := jwt.NewGolangJWTSigner(cfg.JWT, "testsecret")

	hasher := security.NewArgon2Hasher(cfg.Argon2, "testsecret")

	mailer := &email.SMTPMailer{}
	validator := validation.NewGoPlaygroundValidator()
	txMgr := db.NewTxManager(conn)

	userRepo := user.NewRepository(conn)
	userSvc := user.NewService(userRepo)
	userHandler := user.NewHandler(userSvc)

	authRepo := auth.NewRepository(conn)
	authSvcDeps := &auth.Dependencies{
		Repo:     authRepo,
		CfgApp:   cfg.App,
		CfgJWT:   cfg.JWT,
		CfgEmail: cfg.Email,
		Hasher:   hasher,
		Mailer:   mailer,
		Signer:   signer,
		Txmgr:    txMgr,
		UserRepo: userRepo,
	}
	authSvc := auth.NewService(authSvcDeps)
	authHandler := auth.NewHandler(authSvc, cfg.JWT, cfg.Cookie)

	middlewares := []func(http.Handler) http.Handler{}

	deps := &app.Dependencies{
		CfgServer:   cfg.Server,
		Signer:      signer,
		Validator:   validator,
		Router:      router.NewGoexpressRouter(),
		Middlewares: middlewares,
		AuthHandler: authHandler,
		UserHandler: userHandler,
	}
	server, err = app.New(deps)
	if err != nil {
		t.Fatalf("new api: %v", err)
	}

	cleanUpFunc = func() {
		conn.Close()
	}

	return server, cleanUpFunc
}

func TestIntegrationApp_StartAndShutdown(t *testing.T) {
	app, cleanup := setupApp(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the server in a goroutine
	go func() {
		if err := app.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("server error: %v", err)
		}
	}()

	// Wait briefly for server to start
	time.Sleep(300 * time.Millisecond)

	// Make a HTTP request to the root (will likely 404, but server should respond)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+os.Getenv("PORT"), http.NoBody)
	if err != nil {
		t.Fatalf("new http request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("failed to GET: %v", err)
	} else {
		resp.Body.Close()
	}

	// Shutdown the app
	if err := app.Shutdown(); err != nil {
		t.Errorf("failed to shutdown app: %v", err)
	}
}
