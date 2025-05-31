package db

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
)

func Setup(t *testing.T) (*sql.DB, func(string)) {
	t.Helper()
	if err := env.Load("../../.env.testing"); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load("../../config.json")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := Connect(context.Background(), cfg.DB)
	if err != nil {
		t.Fatal(err)
	}

	cleanUpFunc := func(cleanUpQuery string) {
		t.Helper()
		_, err := conn.Exec(cleanUpQuery)
		if err != nil {
			slog.Error("db cleanup failed", "reason", err)
		}
	}

	return conn, cleanUpFunc
}
