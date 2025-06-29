package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/pkg/env"
)

func Setup(t *testing.T) (*sql.DB, *sql.Tx) {
	t.Helper()

	const projRoot = "../../"

	if err := env.Load(projRoot + ".env.testing"); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(projRoot + "config.json")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := NewPostgresDB(context.Background(), cfg.DB)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("unable to begin transaction: %v", err)
	}

	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil {
			t.Logf("unable to rollback transaction: %v", err)
		}
	})

	return conn, tx
}
