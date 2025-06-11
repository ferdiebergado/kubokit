package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	errx "github.com/ferdiebergado/kubokit/internal/pkg/errors"
)

// SafeResponseWriter is an http.ResponseWriter wrapper that prevents wasting resources, race conditions and poor user experience.
//
//nolint:containedctx //This ResponseWriter wrapper requires a context to gracefully handle canceled or timed-out requests.
type SafeResponseWriter struct {
	http.ResponseWriter
	ctx           context.Context
	mu            sync.Mutex
	status        int
	headerWritten bool
	bytesSent     int
}

func NewSafeResponseWriter(ctx context.Context, w http.ResponseWriter) *SafeResponseWriter {
	return &SafeResponseWriter{
		ResponseWriter: w,
		ctx:            ctx,
		status:         http.StatusOK,
	}
}

func (w *SafeResponseWriter) WriteHeader(statusCode int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ctxErr := w.ctx.Err()

	if errx.IsContextError(ctxErr) {
		return
	}

	if w.headerWritten {
		return
	}

	w.ResponseWriter.WriteHeader(statusCode)
	w.status = statusCode
	w.headerWritten = true
}

func (w *SafeResponseWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	ctxErr := w.ctx.Err()
	if errx.IsContextError(ctxErr) {
		return 0, nil
	}

	if !w.headerWritten {
		slog.Warn("invoked Write() without WriteHeader(statusCode)")
		w.ResponseWriter.WriteHeader(http.StatusOK)
		w.status = http.StatusOK
		w.headerWritten = true
	}

	if w.status >= http.StatusInternalServerError {
		slog.Warn("ignoring write due to server error")
		return 0, nil
	}

	n, err := w.ResponseWriter.Write(b)
	w.bytesSent += n
	return n, err
}

func (w *SafeResponseWriter) Status() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *SafeResponseWriter) BytesWritten() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytesSent
}
