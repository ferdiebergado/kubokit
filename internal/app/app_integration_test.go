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
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/user"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func setupApp(t *testing.T) (api *app.App, cleanUpFunc func()) {
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

	signer, err := jwt.NewGolangJWTSigner(cfg.JWT, "testsecret")
	if err != nil {
		t.Fatalf("new jwt signer: %v", err)
	}

	hasher, err := hash.NewArgon2Hasher(cfg.Argon2, "testsecret")
	if err != nil {
		t.Fatalf("new hasher: %v", err)
	}

	mailer := &email.SMTPMailer{}
	validator := validation.NewGoPlaygroundValidator()
	txMgr := db.NewSQLTxManager(conn)

	userRepo := user.NewRepository(conn)
	userSvc := user.NewService(userRepo, hasher)
	userHandler := user.NewHandler(userSvc)

	authRepo := auth.NewRepository(conn)
	authSvcProvider := &auth.ServiceProvider{
		CfgApp:   cfg.App,
		CfgJWT:   cfg.JWT,
		CfgEmail: cfg.Email,
		Hasher:   hasher,
		Mailer:   mailer,
		Signer:   signer,
		Txmgr:    txMgr,
		UserRepo: userRepo,
	}
	authSvc, err := auth.NewService(authRepo, authSvcProvider)
	if err != nil {
		t.Fatalf("failed to create new auth service: %v", err)
	}

	authHandlerProvider := &auth.HandlerProvider{
		CfgJWT:    cfg.JWT,
		CfgCookie: cfg.Cookie,
		Signer:    signer,
	}
	authHandler, err := auth.NewHandler(authSvc, authHandlerProvider)
	if err != nil {
		t.Fatalf("failed to create new auth handler: %v", err)
	}

	middlewares := []func(http.Handler) http.Handler{}
	provider := &app.Provider{
		CfgServer: cfg.Server,
		Signer:    signer,
		Validator: validator,
		Router:    router.NewGoexpressRouter(),
	}
	api, err = app.New(provider, middlewares, authHandler, userHandler)
	if err != nil {
		t.Fatalf("new api: %v", err)
	}

	cleanUpFunc = func() {
		conn.Close()
	}

	return api, cleanUpFunc
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
