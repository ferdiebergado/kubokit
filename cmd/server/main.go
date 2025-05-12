package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/ferdiebergado/kubokit/internal/app"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	ctx := context.Background()

	if err := app.Run(ctx); err != nil {
		slog.Error("Application failed to start.", "reason", err)
		os.Exit(1)
	}
}
