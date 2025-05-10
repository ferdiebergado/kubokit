package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ferdiebergado/slim/internal/config"
)

// Connect creates and validates a database connection.
func Connect(ctx context.Context, opts *config.DBOptions) (*sql.DB, error) {
	slog.Info("Connecting to the database...")
	const dsnFmt = "postgres://%s:%s@%s:%s/%s?sslmode=%s"

	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbName := os.Getenv("DB_NAME")
	dbSSL := os.Getenv("DB_SSLMODE")

	conn, err := sql.Open(opts.Driver, fmt.Sprintf(dsnFmt, dbUser, dbPass, dbHost, dbPort, dbName, dbSSL))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	conn.SetMaxOpenConns(opts.MaxOpenConns)
	conn.SetMaxIdleConns(opts.MaxIdleConns)
	conn.SetConnMaxIdleTime(time.Duration(opts.ConnMaxIdleTime) * time.Second)
	conn.SetConnMaxLifetime(time.Duration(opts.ConnMaxLifetime) * time.Second)

	pingCtx, cancel := context.WithTimeout(ctx, time.Duration(opts.PingTimeout)*time.Second)
	defer cancel()

	if err := conn.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	slog.Info("Connected to the database.", "db", dbName)

	return conn, nil
}
