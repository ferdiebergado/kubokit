package logging

import (
	"io"
	"log/slog"
	"strings"
)

func SetupLogger(appEnv, logLevel string, out io.Writer) {
	opts := &slog.HandlerOptions{
		Level: stringToLogLevel(logLevel),
	}

	var handler slog.Handler = slog.NewTextHandler(out, opts)

	if appEnv == "production" {
		handler = slog.NewJSONHandler(out, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)
}

func stringToLogLevel(levelStr string) slog.Level {
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARNING", "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
