package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func TestMiddleware_CheckContentType(t *testing.T) {
	t.Parallel()

	const (
		defaultContent = "test"
		errContent     = `{"message":"Invalid input."}`
	)

	var tests = []struct {
		name, method, contentType, wantBody string
		wantCode                            int
	}{
		{"Correct Content-Type Post", http.MethodPost, web.MimeJSON, defaultContent, http.StatusOK},
		{"Correct Content-Type Put", http.MethodPut, web.MimeJSON, defaultContent, http.StatusOK},
		{"Correct Content-Type Patch", http.MethodPatch, web.MimeJSON, defaultContent, http.StatusOK},
		{
			"Correct Content-Type with charset",
			http.MethodPost,
			"application/json; charset=utf-8",
			errContent,
			http.StatusUnsupportedMediaType,
		},
		{"Other Content-Type", http.MethodPost, "text/html; charset=utf-8", errContent, http.StatusUnsupportedMediaType},
		{"Empty Content-Type", http.MethodPost, "", errContent, http.StatusUnsupportedMediaType},
		{"Get request", http.MethodGet, "", defaultContent, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, err := w.Write([]byte(defaultContent))
				if err != nil {
					const status = http.StatusInternalServerError
					http.Error(w, http.StatusText(status), status)
					return
				}
			})

			req, rec := httptest.NewRequest(tt.method, "/test", http.NoBody), httptest.NewRecorder()
			req.Header.Set(web.HeaderContentType, tt.contentType)

			middleware.CheckContentType(handler).ServeHTTP(rec, req)

			wantCode, gotCode := tt.wantCode, rec.Code
			if gotCode != wantCode {
				t.Errorf("rec.Code = %d\nwant: %d", gotCode, wantCode)
			}

			wantBody, gotBody := tt.wantBody, strings.TrimSuffix(rec.Body.String(), "\n")
			if gotBody != wantBody {
				t.Errorf("rec.Body.String() = %q\nwant: %q", gotBody, wantBody)
			}
		})
	}
}
