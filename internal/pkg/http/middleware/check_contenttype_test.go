package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpx "github.com/ferdiebergado/kubokit/internal/pkg/http"
	"github.com/ferdiebergado/kubokit/internal/pkg/http/middleware"
)

func TestCheckContentType(t *testing.T) {
	t.Parallel()

	const (
		errMsg = `{"message":"Invalid input."}`
		body   = "test"
	)

	var tests = []struct {
		name        string
		contentType string
		method      string
		code        int
		body        string
		setHeader   bool
	}{
		{"Correct Content-Type Post", httpx.MimeJSON, http.MethodPost, http.StatusOK, body, true},
		{"Correct Content-Type Put", httpx.MimeJSON, http.MethodPut, http.StatusOK, body, true},
		{"Correct Content-Type Patch", httpx.MimeJSON, http.MethodPatch, http.StatusOK, body, true},
		{
			"Correct Content-Type with charset",
			"application/json; charset=utf-8",
			http.MethodPost,
			http.StatusUnsupportedMediaType,
			errMsg,
			true,
		},
		{"Other Content-Type", "text/html; charset=utf-8", http.MethodPost, http.StatusUnsupportedMediaType, errMsg, true},
		{"Empty Content-Type", "", http.MethodPost, http.StatusUnsupportedMediaType, errMsg, true},
		{"Header not present", "", http.MethodPost, http.StatusUnsupportedMediaType, errMsg, false},
		{"Get request", "", http.MethodGet, http.StatusOK, body, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			})

			req, rr := httptest.NewRequest(tt.method, "/test", nil), httptest.NewRecorder()
			if tt.setHeader {
				req.Header.Set(httpx.HeaderContentType, tt.contentType)
			}

			middleware.CheckContentType(handler).ServeHTTP(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			wantCode, gotCode := tt.code, res.StatusCode
			if gotCode != wantCode {
				t.Errorf("CheckContentType() = %d, want: %d", gotCode, wantCode)
			}

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			wantBody, gotBody := tt.body, strings.TrimSuffix(string(body), "\n")
			if gotBody != wantBody {
				t.Errorf("rr.Body = %q, want: %q", gotBody, wantBody)
			}
		})
	}
}
