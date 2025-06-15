package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/ferdiebergado/kubokit/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// NewConnection creates and validates a database connection.
func NewConnection(signalCtx context.Context, cfg *config.DB) (*sql.DB, error) {
	slog.Info("Connecting to the database...")
	const dsnFmt = "postgres://%s:%s@%s:%s/%s?sslmode=%s"

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	dbSSL := os.Getenv("DB_SSLMODE")

	dsn := fmt.Sprintf(dsnFmt, dbUser, dbPass, dbHost, dbPort, dbName, dbSSL)
	conn, err := sql.Open(cfg.Driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(cfg.MaxOpenConns)
	conn.SetMaxIdleConns(cfg.MaxIdleConns)
	conn.SetConnMaxIdleTime(cfg.ConnMaxIdleTime.Duration)
	conn.SetConnMaxLifetime(cfg.ConnMaxLifetime.Duration)

	pingCtx, cancel := context.WithTimeout(signalCtx, cfg.PingTimeout.Duration)
	defer cancel()

	if err := conn.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	slog.Info("Connected to the database.", "db", dbName)

	return conn, nil
}
