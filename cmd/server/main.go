package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ferdiebergado/kubokit/internal/app"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	if err := app.Run(ctx); err != nil {
		slog.Error("Application failed to start.", "reason", err)
		os.Exit(1)
	}
}
