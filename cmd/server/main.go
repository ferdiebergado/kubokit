package main

import (
	"log/slog"
	"os"

	"github.com/ferdiebergado/kubokit/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		slog.Error("Server failed to start.", "reason", err)
		os.Exit(1)
	}
}
