package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
)

const defaultStatus = http.StatusOK

// SafeResponseWriter is an http.ResponseWriter wrapper that prevents wasting resources, race conditions and poor user experience.
//
//nolint:containedctx //This ResponseWriter wrapper requires a context to gracefully handle canceled or timed-out requests.
type SafeResponseWriter struct {
	http.ResponseWriter
	ctx context.Context

	status        int
	headerWritten bool
	mu            sync.Mutex
	bytesSent     atomic.Int64
}

func (w *SafeResponseWriter) WriteHeader(statusCode int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ctx.Err(); err != nil {
		warnCtxErr(err)
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
	if err := w.ctx.Err(); err != nil {
		warnCtxErr(err)
		return 0, nil
	}

	w.mu.Lock()

	if !w.headerWritten {
		slog.Warn("Write() called without WriteHeader()", "default_status", defaultStatus)
		w.ResponseWriter.WriteHeader(defaultStatus)
		w.status = defaultStatus
		w.headerWritten = true
	}

	if w.status >= http.StatusInternalServerError {
		slog.Warn("write was ignored due to server error")
		return 0, nil
	}

	w.mu.Unlock()

	n, err := w.ResponseWriter.Write(b)
	w.bytesSent.Add(int64(n))
	return n, err
}

func (w *SafeResponseWriter) Status() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func (w *SafeResponseWriter) BytesWritten() int {
	return int(w.bytesSent.Load())
}

func NewSafeResponseWriter(ctx context.Context, w http.ResponseWriter) *SafeResponseWriter {
	return &SafeResponseWriter{
		ResponseWriter: w,
		ctx:            ctx,
		status:         defaultStatus,
	}
}

func warnCtxErr(err error) {
	slog.Warn("context error occurred", "error", err)
}
