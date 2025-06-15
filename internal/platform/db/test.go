package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/ferdiebergado/gopherkit/env"
	"github.com/ferdiebergado/kubokit/internal/config"
)

func Setup(t *testing.T) (dbConn *sql.DB, cleanUpFunc func(string)) {
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

	cleanUpFunc = func(cleanUpQuery string) {
		t.Helper()
		_, err := conn.Exec(cleanUpQuery)
		if err != nil {
			t.Logf("cannot cleanup db: %v", err)
		}
	}

	return conn, cleanUpFunc
}

func NewTransaction(t *testing.T) (tx *sql.Tx, cleanUpFunc func()) {
	t.Helper()

	conn, _ := Setup(t)
	tx, err := conn.Begin()
	if err != nil {
		t.Fatalf("unable to begin transaction: %v", err)
	}
	cleanUpFunc = func() {
		if err := tx.Rollback(); err != nil {
			t.Logf("failed to rollback transaction: %v", err)
		}
	}
	return tx, cleanUpFunc
}
