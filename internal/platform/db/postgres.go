package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ferdiebergado/kubokit/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// NewPostgresDB creates and validates a postgres database connection.
func NewPostgresDB(signalCtx context.Context, cfg *config.DB) (*sql.DB, error) {
	slog.Info("Connecting to the database...")

	const dsnFmt = "postgres://%s:%s@%s:%d/%s?sslmode=%s"
	dsn := fmt.Sprintf(dsnFmt, cfg.User, cfg.Pass, cfg.Host, cfg.Port, cfg.Name, cfg.SSLMode)
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

	slog.Info("Connected to the database.", "db", cfg.Name)

	return conn, nil
}

func IsUniqueConstraintViolation(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "SQLSTATE 23505")
}
