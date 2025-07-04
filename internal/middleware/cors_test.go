package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/middleware"
)

func TestMiddleware_CORS(t *testing.T) {
	t.Parallel()

	const allowedOrigin = "localhost:3000"

	tests := []struct {
		name, method, origin string
		code                 int
		headers              map[string]string
	}{
		{
			name:   "GET method with allowed origin",
			method: http.MethodGet,
			origin: allowedOrigin,
			code:   http.StatusOK,
			headers: map[string]string{
				middleware.HeaderAllowOrigin:  allowedOrigin,
				middleware.HeaderAllowMethods: middleware.AllowedMethods,
				middleware.HeaderAllowHeaders: middleware.AllowedHeaders,
				middleware.HeaderAllowCreds:   middleware.AllowedCreds,
			},
		},
		{
			name:   "POST method with allowed origin",
			method: http.MethodPost,
			origin: allowedOrigin,
			code:   http.StatusOK,
			headers: map[string]string{
				middleware.HeaderAllowOrigin:  allowedOrigin,
				middleware.HeaderAllowMethods: middleware.AllowedMethods,
				middleware.HeaderAllowHeaders: middleware.AllowedHeaders,
				middleware.HeaderAllowCreds:   middleware.AllowedCreds,
			},
		},
		{
			name:   "OPTIONS method with allowed origin",
			method: http.MethodOptions,
			origin: allowedOrigin,
			code:   http.StatusNoContent,
			headers: map[string]string{
				middleware.HeaderAllowOrigin:  allowedOrigin,
				middleware.HeaderAllowMethods: middleware.AllowedMethods,
				middleware.HeaderAllowHeaders: middleware.AllowedHeaders,
				middleware.HeaderAllowCreds:   middleware.AllowedCreds,
			},
		},
		{
			name:    "GET method with unknown origin",
			method:  http.MethodGet,
			origin:  "example.com",
			code:    http.StatusOK,
			headers: map[string]string{},
		},
		{
			name:    "PUT method with unknown origin",
			method:  http.MethodPut,
			origin:  "example.com",
			code:    http.StatusOK,
			headers: map[string]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(tc.method, "/", http.NoBody)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			mw := middleware.CORS(allowedOrigin)
			mw(handler).ServeHTTP(rec, req)

			gotCode, wantCode := rec.Code, tc.code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d, want: %d", gotCode, wantCode)
			}

			for header, val := range tc.headers {
				gotHeader := rec.Header().Get(header)
				wantHeader := val

				if gotHeader != wantHeader {
					t.Errorf("rec.Header().Get(%q) = %q, want: %q", header, gotHeader, wantHeader)
				}
			}
		})
	}
}
