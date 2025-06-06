package errors

import (
	"context"
	"errors"
	"log/slog"
)

func IsContextError(err error) bool {
	if errors.Is(err, context.Canceled) {
		slog.Warn("request has been canceled")
		return true
	}

	if errors.Is(err, context.DeadlineExceeded) {
		slog.Warn("request timed out")
		return true
	}

	return false
}
