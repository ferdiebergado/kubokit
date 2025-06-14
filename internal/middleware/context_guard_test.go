package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ferdiebergado/kubokit/internal/middleware"
)

func TestContextGuard(t *testing.T) {
	t.Parallel()

	const header = "X-Handler-Called"

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(header, "true")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			const status = http.StatusInternalServerError
			http.Error(w, http.StatusText(status), status)
			return
		}
	}

	tests := []struct {
		name    string
		code    int
		header  string
		ctxFunc func() (context.Context, context.CancelFunc, func())
	}{
		{"Normal request", http.StatusOK, "true", func() (context.Context, context.CancelFunc, func()) {
			return context.Background(), nil, nil
		}},
		{"Canceled Request", http.StatusRequestTimeout, "", func() (context.Context, context.CancelFunc, func()) {
			ctx, cancel := context.WithCancel(context.Background())
			return ctx, cancel, nil
		}},
		{"Request timed out", http.StatusRequestTimeout, "", func() (context.Context, context.CancelFunc, func()) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
			return ctx, cancel, func() { time.Sleep(1 * time.Millisecond) }
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			ctx, cancel, sleepFunc := tt.ctxFunc()
			if cancel != nil {
				cancel()
			}
			if sleepFunc != nil {
				sleepFunc()
			}
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", http.NoBody)
			mw := middleware.ContextGuard(http.HandlerFunc(handler))
			mw.ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tt.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			gotHeader, wantHeader := rec.Header().Get(header), tt.header
			if gotHeader != wantHeader {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", header, gotHeader, wantHeader)
			}
		})
	}
}
