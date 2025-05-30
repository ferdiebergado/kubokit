package auth_test

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"testing"
	"time"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/auth"
	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/db"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func setup() (*sql.DB, func(), error) {
	if err := env.Load("../../.env.testing"); err != nil {
		log.Fatal(err)
	}

	cfg, err := config.Load("../../config.json")
	if err != nil {
		return nil, nil, err
	}

	conn, err := db.Connect(context.Background(), cfg.DB)
	if err != nil {
		return nil, nil, err
	}

	return conn, func() {
		_, err := conn.Exec("TRUNCATE users")
		if err != nil {
			slog.Error("reset db failed", "reason", err)
		}
	}, nil
}

func TestIntegrationRepository_CreateUser(t *testing.T) {
	t.Parallel()
	conn, cleanUp, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanUp()

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
}
