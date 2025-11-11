package db

import (
	"database/sql"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
)

func Setup(t *testing.T) (*sql.DB, *sql.Tx) {
	t.Helper()

	const projRoot = "../../"

	if err := env.Load(projRoot + ".env.testing"); err != nil {
		t.Fatalf("failed to load environment file: %v", err)
	}

	cfg, err := config.Load(projRoot + "config.json")
	if err != nil {
		t.Fatalf("failed to load config file: %v", err)
	}

	conn, err := NewPostgresDB(t.Context(), cfg.DB)
	if err != nil {
		t.Fatalf("failed create database: %v", err)
	}

	tx, err := conn.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("failed to begin transaction: %v", err)
	}

	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil {
			t.Logf("failed to rollback transaction: %v", err)
		}
	})

	return conn, tx
}
