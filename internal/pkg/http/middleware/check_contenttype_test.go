package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/pkg/http/middleware"
)

func TestMiddleware_CheckContentType(t *testing.T) {
	t.Parallel()

	const (
		defaultContent = "test"
		errContent     = `{"message":"Invalid input."}`
	)

	var tests = []struct {
		name        string
		method      string
		contentType string
		wantCode    int
		wantBody    string
	}{
		{"Correct Content-Type Post", http.MethodPost, httpx.MimeJSON, http.StatusOK, defaultContent},
		{"Correct Content-Type Put", http.MethodPut, httpx.MimeJSON, http.StatusOK, defaultContent},
		{"Correct Content-Type Patch", http.MethodPatch, httpx.MimeJSON, http.StatusOK, defaultContent},
		{
			"Correct Content-Type with charset",
			http.MethodPost,
			"application/json; charset=utf-8",
			http.StatusUnsupportedMediaType,
			errContent,
		},
		{"Other Content-Type", http.MethodPost, "text/html; charset=utf-8", http.StatusUnsupportedMediaType, errContent},
		{"Empty Content-Type", http.MethodPost, "", http.StatusUnsupportedMediaType, errContent},
		{"Header not present", http.MethodPost, "", http.StatusUnsupportedMediaType, errContent},
		{"Get request", http.MethodGet, "", http.StatusOK, defaultContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, err := w.Write([]byte(defaultContent))
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			})

			req, rr := httptest.NewRequest(tt.method, "/test", http.NoBody), httptest.NewRecorder()
			if tt.contentType != "" {
				req.Header.Set(httpx.HeaderContentType, tt.contentType)
			}

			middleware.CheckContentType(handler).ServeHTTP(rr, req)

			wantCode, gotCode := tt.wantCode, rr.Code
			if gotCode != wantCode {
				t.Errorf("CheckContentType() = %d, want: %d", gotCode, wantCode)
			}

			wantBody, gotBody := tt.wantBody, strings.TrimSuffix(rr.Body.String(), "\n")
			if gotBody != wantBody {
				t.Errorf("\nrr.Body.Bytes() = %q\nwant: %q\n", gotBody, wantBody)
			}
		})
	}
}
