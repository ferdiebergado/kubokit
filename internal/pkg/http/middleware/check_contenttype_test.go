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

	const errMsg = `{"message":"Invalid input."}`
	var tests = []struct {
		name        string
		contentType string
		code        int
		body        string
		setHeader   bool
	}{
		{"Correct Content-Type", httpx.MimeJSON, http.StatusOK, "test", true},
		{
			"Correct Content-Type with charset",
			"application/json; charset=utf-8",
			http.StatusUnsupportedMediaType,
			errMsg,
			true,
		},
		{"Other Content-Type", "text/html; charset=utf-8", http.StatusUnsupportedMediaType, errMsg, true},
		{"Empty Content-Type", "", http.StatusUnsupportedMediaType, errMsg, true},
		{"Header not present", "", http.StatusUnsupportedMediaType, errMsg, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.setHeader {
				req.Header.Set(httpx.HeaderContentType, tt.contentType)
			}
			rr := httptest.NewRecorder()
			fakeMW := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("test"))
			})
			middleware.CheckContentType(fakeMW).ServeHTTP(rr, req)

			res := rr.Result()
			defer res.Body.Close()

			wantCode := tt.code
			gotCode := res.StatusCode
			if gotCode != wantCode {
				t.Errorf("CheckContentType() = %d, want: %d", gotCode, wantCode)
			}

			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			wantBody := tt.body
			gotBody := strings.TrimSuffix(string(body), "\n")
			if gotBody != wantBody {
				t.Errorf("rr.Body = %q, want: %q", gotBody, wantBody)
			}
		})
	}
}
