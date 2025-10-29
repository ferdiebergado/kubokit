package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ferdiebergado/kubokit/internal/middleware"
	"github.com/ferdiebergado/kubokit/internal/pkg/message"
	"github.com/ferdiebergado/kubokit/internal/pkg/web"
)

func TestMiddleware_CheckContentType(t *testing.T) {
	t.Parallel()

	const (
		headerCalled   = "X-Handler-Called"
		defaultContent = "test"
		errContent     = `{"message":"Invalid input."}`
	)

	tests := []struct {
		name, method, contentType, wantBody, headerCalled string
		wantCode                                          int
	}{
		{"Correct Content-Type Post", http.MethodPost, web.MimeJSON, defaultContent, "true", http.StatusOK},
		{"Correct Content-Type Put", http.MethodPut, web.MimeJSON, defaultContent, "true", http.StatusOK},
		{"Correct Content-Type Patch", http.MethodPatch, web.MimeJSON, defaultContent, "true", http.StatusOK},
		{
			"Correct Content-Type with charset",
			http.MethodPost,
			"application/json; charset=utf-8",
			defaultContent,
			"true",
			http.StatusOK,
		},
		{"Other Content-Type", http.MethodPost, "text/html; charset=utf-8", errContent, "", http.StatusUnsupportedMediaType},
		{"Empty Content-Type", http.MethodPost, "", errContent, "", http.StatusUnsupportedMediaType},
		{"Get request", http.MethodGet, "", defaultContent, "true", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(headerCalled, "true")

				_, err := w.Write([]byte(defaultContent))
				if err != nil {
					const status = http.StatusInternalServerError
					http.Error(w, http.StatusText(status), status)
					return
				}
			})

			req, rec := httptest.NewRequest(tc.method, "/test", http.NoBody), httptest.NewRecorder()
			req.Header.Set(web.HeaderContentType, tc.contentType)

			middleware.CheckContentType(handler).ServeHTTP(rec, req)

			wantCode, gotCode := tc.wantCode, rec.Code
			if gotCode != wantCode {
				t.Errorf(message.FmtErrStatusCode, gotCode, wantCode)
			}

			gotHeaderCalled, wantHeaderCalled := rec.Header().Get(headerCalled), tc.headerCalled
			if gotHeaderCalled != wantHeaderCalled {
				t.Errorf("rec.Header().Get(%q) = %q, want: %q", headerCalled, gotHeaderCalled, wantHeaderCalled)
			}

			wantBody, gotBody := tc.wantBody, strings.TrimSuffix(rec.Body.String(), "\n")
			if gotBody != wantBody {
				t.Errorf("rec.Body.String() = %q, want: %q", gotBody, wantBody)
			}
		})
	}
}
