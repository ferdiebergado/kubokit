package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/config"
	"github.com/ferdiebergado/kubokit/internal/middleware"
)

func TestMiddleware_CORS(t *testing.T) {
	t.Parallel()

	const (
		headerCalled = "X-Handler-Called"
		sameOrigin   = "http://localhost:3000"
		otherOrigin  = "http://example.com"
	)

	tests := []struct {
		name, method, origin, headerCalled string
		code                               int
	}{
		{
			name:   "Preflight request from same origin",
			method: http.MethodOptions,
			origin: sameOrigin,
			code:   http.StatusNoContent,
		},
		{
			name:         "GET request from same origin",
			method:       http.MethodGet,
			origin:       sameOrigin,
			code:         http.StatusOK,
			headerCalled: "true",
		},
		{
			name:   "Preflight request from other origin",
			method: http.MethodOptions,
			origin: otherOrigin,
			code:   http.StatusNoContent,
		},
		{
			name:         "POST request from other origin",
			method:       http.MethodPost,
			origin:       otherOrigin,
			code:         http.StatusOK,
			headerCalled: "true",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(headerCalled, "true")
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(tc.method, "/", http.NoBody)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()

			corsConfig := &config.CORS{
				AllowedOrigin:    "http://localhost:5173",
				AllowedMethods:   []string{"GET", "POST"},
				AllowedHeaders:   []string{"Content-Type", "Authorization"},
				AllowCredentials: "true",
			}

			mw := middleware.CORS(corsConfig)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			headers := map[string]string{
				middleware.HeaderAllowOrigin:      corsConfig.AllowedOrigin,
				middleware.HeaderAllowMethods:     strings.Join(corsConfig.AllowedMethods, ","),
				middleware.HeaderAllowHeaders:     strings.Join(corsConfig.AllowedHeaders, ","),
				middleware.HeaderAllowCredentials: corsConfig.AllowCredentials,
				headerCalled:                      tc.headerCalled,
			}

			for header, val := range headers {
				gotHeader := rec.Header().Get(header)
				wantHeader := val

				if gotHeader != wantHeader {
					t.Errorf("rec.Header().Get(%q) = %q, want: %q", header, gotHeader, wantHeader)
				}
			}
		})
	}
}
