package auth_test

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var conn *sql.DB

func TestMain(m *testing.M) {
	if err := env.Load("../../.env.testing"); err != nil {
		log.Fatal(err)
	}

	cfg, err := config.Load("../../config.json")
	if err != nil {
		log.Fatal(err)
	}

	conn, err = db.Connect(context.Background(), cfg.DB)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func resetDB() {
	_, err := conn.Exec("TRUNCATE users")
	if err != nil {
		slog.Error("reset db failed", "reason", err)
	}
}

func TestIntegrationRepository_CreateUser(t *testing.T) {
	t.Parallel()
	repo := &auth.Repository{
		DB: conn,
	}

	params := auth.CreateUserParams{
		Email:        "test@example.com",
		PasswordHash: "hashed",
	}
	ctx := context.Background()
	u, err := repo.CreateUser(ctx, params)
	if err != nil {
		t.Fatal(err)
	}

	if u.Email != params.Email {
		t.Errorf("u.Email = %s, want: %s", u.Email, params.Email)
	}

	if u.CreatedAt.IsZero() {
		t.Errorf("u.CreatedAt = %v, want: %v", u.CreatedAt, time.Now())
	}

	t.Cleanup(resetDB)
}
