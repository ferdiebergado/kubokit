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
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
	"github.com/ferdiebergado/kubokit/internal/platform/db"
	"github.com/ferdiebergado/kubokit/internal/platform/email"
	"github.com/ferdiebergado/kubokit/internal/platform/hash"
	"github.com/ferdiebergado/kubokit/internal/platform/jwt"
	"github.com/ferdiebergado/kubokit/internal/platform/router"
	"github.com/ferdiebergado/kubokit/internal/platform/validation"
	"github.com/ferdiebergado/kubokit/internal/provider"

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

	provider := &provider.Provider{
		Cfg:       cfg,
		DB:        conn,
		Signer:    signer,
		Mailer:    &email.SMTPMailer{},
		Validator: validation.NewGoPlaygroundValidator(),
		Hasher:    hasher,
		Router:    router.NewGoexpressRouter(),
		TxMgr:     db.NewSQLTxManager(conn),
	}

	middlewares := []func(http.Handler) http.Handler{}
	api, err = app.New(provider, middlewares)
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
